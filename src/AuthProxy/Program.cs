using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using AuthProxy.Configuration;
using AuthProxy.Infrastructure;
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
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.TokenIssuer?.Audience);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.TokenIssuer?.Issuer);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.TokenIssuer?.Expiration);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.TokenIssuer?.SigningSecret);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.Authority);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.ClientId);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProvider?.ClientSecret); // TODO: Only if needed (depending on auth flow)

// Add the YARP Direct HTTP Forwarder.
builder.Services.AddHttpForwarder();

// Add authentication services.
// TODO: External key for cookie and other crypto operations?
// TODO: Based on config which providers!
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
if (authProxyConfig.Authentication.IdentityProvider.Type == IdentityProviderType.OpenIdConnect)
{
    authenticationBuilder.AddOpenIdConnect(options =>
    {
        options.ClaimActions.Clear(); // Don't remove any incoming claims.
        options.Authority = authProxyConfig.Authentication.IdentityProvider.Authority;
        options.TokenValidationParameters.ValidAudiences = new[] { authProxyConfig.Authentication.IdentityProvider.Audience };
        options.ClientId = authProxyConfig.Authentication.IdentityProvider.ClientId;
        options.ClientSecret = authProxyConfig.Authentication.IdentityProvider.ClientSecret;
        options.CallbackPath = authProxyConfig.Authentication.IdentityProvider.CallbackPath;
    });
}
// else if (authProxyConfig.Authentication.IdentityProvider.Type == IdentityProviderType.JwtBearer)
// {
//     authenticationBuilder.AddJwtBearer(options =>
//     {
//         // TODO: Make configurable where the incoming JWT is found.
//         // https://stackoverflow.com/questions/56857905/how-to-customize-bearer-header-keyword-in-asp-net-core-for-jwtbearer-and-system
//         options.Authority = authProxyConfig.Authentication.IdentityProvider.Authority;
//     });
// }
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
var customTransformer = new YarpHttpTransformer(authProxyConfig.Authentication.Cookie.Name, new TokenIssuer(authProxyConfig.Authentication.TokenIssuer.Audience, authProxyConfig.Authentication.TokenIssuer.Issuer, authProxyConfig.Authentication.TokenIssuer.Expiration.Value, authProxyConfig.Authentication.TokenIssuer.SigningSecret));
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