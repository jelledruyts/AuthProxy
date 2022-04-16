using System.IdentityModel.Tokens.Jwt;
using System.Net;
using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind("AuthProxy", authProxyConfig);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.Cookie);
builder.Services.AddSingleton<AuthProxyConfig>(authProxyConfig);

// Construct identity providers.
var identityProviderFactory = new IdentityProviderFactory(authProxyConfig);
builder.Services.AddSingleton<IdentityProviderFactory>(identityProviderFactory);

// Add YARP services.
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton<YarpRequestHandler>();

// Add authentication services.
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.

// Add cookie authentication as the final user session provider.
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
authenticationBuilder.AddCookie(options =>
{
    // TODO: Also rename other cookies (.AspNetCore.* for correlation and nonce for example)
    // TODO: External key for cookie and other crypto operations?
    options.Cookie.Name = authProxyConfig.Authentication.Cookie.Name;
    options.Events = new CookieAuthenticationEvents
    {
        OnSigningIn = (context) =>
        {
            // Create a persistent browser cookie if configured.
            context.Properties.IsPersistent = authProxyConfig.Authentication.Cookie.IsPersistent;
            return Task.CompletedTask;
        }
    };
});

// Add an authentication service for each IdP.
foreach (var identityProvider in identityProviderFactory.IdentityProviders)
{
    identityProvider.AddAuthentication(authenticationBuilder);
}

var app = builder.Build();

// Configure authentication.
app.UseAuthentication();

// Map a login path per IdP (e.g. "/.auth/login/<name>").
foreach (var identityProvider in identityProviderFactory.IdentityProviders)
{
    app.Map(identityProvider.LoginPath, identityProvider.RequestLogin);
}

// Map a global logout path.
var logoutPath = Defaults.LogoutPath; // TODO: Make this configurable.
var postLogoutReturnUrlQueryParameterName = Defaults.PostLogoutReturnUrlQueryParameterName; // TODO: Make configurable.
app.Map(logoutPath, async httpContext =>
{
    var returnUrl = "/";
    if (httpContext.Request.Query.TryGetValue(postLogoutReturnUrlQueryParameterName, out var postLogoutReturnUrlValue))
    {
        returnUrl = postLogoutReturnUrlValue.First();
    }
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        // TODO: If configured, also trigger Single Sign-Out across all authenticated IdPs.
        await httpContext.SignOutAsync(new AuthenticationProperties { RedirectUri = returnUrl });
    }
    httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
    httpContext.Response.Headers.Location = returnUrl;
});

// Map everything else to YARP.
var handler = app.Services.GetRequiredService<YarpRequestHandler>();
app.Map("/{**catch-all}", handler.HandleRequest);

app.Run();