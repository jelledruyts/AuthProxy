using System.Diagnostics;
using System.Net;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Yarp.ReverseProxy.Forwarder;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind(AuthProxyConfig.ConfigSectionName, authProxyConfig);
ArgumentNullException.ThrowIfNull(authProxyConfig.Backend?.Url);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.Cookie?.Name);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.Authority);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.ClientId);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.ClientSecret); // TODO: Only if needed (depending on auth flow)

// Add the YARP Direct HTTP Forwarder.
builder.Services.AddHttpForwarder();

// Add authentication services.
// TODO: External key for cookie and other crypto operations?
// TODO: Based on config which providers!
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
if (authProxyConfig.Authentication.IdentityProvider.Type == IdentityProviderType.OpenIdConnect)
{
    authenticationBuilder.AddOpenIdConnect(options =>
    {
        options.Authority = authProxyConfig.Authentication.IdentityProvider.Authority;
        options.TokenValidationParameters.ValidAudiences = new[] { authProxyConfig.Authentication.IdentityProvider.Audience };
        options.ClientId = authProxyConfig.Authentication.IdentityProvider.ClientId;
        options.ClientSecret = authProxyConfig.Authentication.IdentityProvider.ClientSecret;
        options.CallbackPath = authProxyConfig.Authentication.IdentityProvider.CallbackPath;
    });
}
// authenticationBuilder.AddJwtBearer(options =>
// {
//     options.Authority = "https://login.microsoftonline.com/identitysamples.onmicrosoft.com/v2.0";
// });
authenticationBuilder.AddCookie(options =>
{
    // TODO: Also rename other cookies (.AspNetCore.* for correlation and nonce for example)
    options.Cookie.Name = authProxyConfig.Authentication.Cookie.Name;
});

var app = builder.Build();

// Configure authentication.
app.UseAuthentication();

// Configure YARP.
var forwarder = app.Services.GetRequiredService<IHttpForwarder>();
var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
{
    UseProxy = false,
    AllowAutoRedirect = false,
    AutomaticDecompression = DecompressionMethods.None,
    UseCookies = false,
    ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
});

var defaultTransformer = HttpTransformer.Default;
var customTransformer = new CustomTransformer();
var requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };

// Map endpoints.
app.Map("/{**catch-all}", async httpContext =>
{
    var isAuth = httpContext.User.Identity?.IsAuthenticated;
    if (isAuth != true)
    {
        await httpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
    }
    else
    {
        var error = await forwarder.SendAsync(httpContext, authProxyConfig.Backend.Url, httpClient, requestOptions, customTransformer);
        if (error != ForwarderError.None)
        {
            var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
            var exception = errorFeature?.Exception;
            // TODO: Log
        }
    }
});

app.Run();

class CustomTransformer : HttpTransformer
{
    /// <summary>
    /// A callback that is invoked prior to sending the proxied request. All HttpRequestMessage fields are
    /// initialized except RequestUri, which will be initialized after the callback if no value is provided.
    /// See <see cref="RequestUtilities.MakeDestinationAddress(string, PathString, QueryString)"/> for constructing a custom request Uri.
    /// The string parameter represents the destination URI prefix that should be used when constructing the RequestUri.
    /// The headers are copied by the base implementation, excluding some protocol headers like HTTP/2 pseudo headers (":authority").
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyRequest">The outgoing proxy request.</param>
    /// <param name="destinationPrefix">The uri prefix for the selected destination server which can be used to create the RequestUri.</param>
    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await HttpTransformer.Default.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

        // TODO: Remove auth cookie in the request towards the app as it's internal to the proxy.

        // Add custom headers as required.
        proxyRequest.Headers.Add("X-Auth-Request", "OK");

        // Suppress the original request header, use the one from the destination Uri.
        proxyRequest.Headers.Host = null;
    }

    /// <summary>
    /// A callback that is invoked when the proxied response is received. The status code and reason phrase will be copied
    /// to the HttpContext.Response before the callback is invoked, but may still be modified there. The headers will be
    /// copied to HttpContext.Response.Headers by the base implementation, excludes certain protocol headers like
    /// `Transfer-Encoding: chunked`.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination. This can be null if the destination did not respond.</param>
    /// <returns>A bool indicating if the response should be proxied to the client or not. A derived implementation 
    /// that returns false may send an alternate response inline or return control to the caller for it to retry, respond, 
    /// etc.</returns>
    public override async ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse)
    {
        // Perform default behavior.
        var shouldProxy = await HttpTransformer.Default.TransformResponseAsync(httpContext, proxyResponse);

        // Copy the relevant response headers.
        if (shouldProxy)
        {
            // Add custom headers as required.
            httpContext.Response.Headers.Add("X-Auth-Response", "OK");
        }
        return shouldProxy;
    }

    /// <summary>
    /// A callback that is invoked after the response body to modify trailers, if supported. The trailers will be
    /// copied to the HttpContext.Response by the base implementation.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination.</param>
    public override ValueTask TransformResponseTrailersAsync(HttpContext httpContext, HttpResponseMessage proxyResponse)
    {
        // Perform default behavior.
        return HttpTransformer.Default.TransformResponseTrailersAsync(httpContext, proxyResponse);
    }
}