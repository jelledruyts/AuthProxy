using System.IdentityModel.Tokens.Jwt;
using AuthProxy.Configuration;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind("AuthProxy", authProxyConfig);
authProxyConfig.Validate(); // TODO: Validate upon actual usage (at startup, not at runtime) rather than without context upfront here?
builder.Services.AddSingleton<AuthProxyConfig>(authProxyConfig);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication?.IdentityProviders);
var defaultIdentityProvider = authProxyConfig.Authentication.DefaultIdentityProvider;

// Add YARP services.
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton<YarpRequestHandler>();

// Add authentication services.
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);

// Add cookie authentication as the final user session provider.
authenticationBuilder.AddCookie(options =>
{
    // TODO: Also rename other cookies (.AspNetCore.* for correlation and nonce for example)
    // TODO: External key for cookie and other crypto operations?
    options.Cookie.Name = authProxyConfig.Authentication.Cookie!.Name;
});

// Add all identity providers as authentication services.
if (defaultIdentityProvider != null)
{
    // Add an authentication service for the default IdP (e.g. "/.auth/login").
    // Note that it will be added again later on, but in order to get a clean URL for the case where
    // there's only a single IdP, it has to be added specifically as the login callback path
    // has to be unique for each registered authentication service.
    authenticationBuilder.AddIdentityProvider(defaultIdentityProvider, authProxyConfig.Authentication.GetDefaultAuthenticationScheme(), authProxyConfig.Authentication.GetDefaultLoginCallbackPath());
}
foreach (var identityProvider in authProxyConfig.Authentication.IdentityProviders)
{
    authenticationBuilder.AddIdentityProvider(identityProvider, authProxyConfig.Authentication.GetAuthenticationScheme(identityProvider), authProxyConfig.Authentication.GetLoginCallbackPath(identityProvider));
}

var app = builder.Build();

// Configure authentication.
app.UseAuthentication();

// Map login paths for identity providers.
if (defaultIdentityProvider != null)
{
    // Map a login path for the default IdP (e.g. "/.auth/login").
    app.MapIdentityProviderLogin(authProxyConfig.Authentication.GetDefaultAuthenticationScheme(), authProxyConfig.Authentication.GetDefaultLoginPath());
}
foreach (var identityProvider in authProxyConfig.Authentication.IdentityProviders)
{
    // Map a login path per IdP (e.g. "/.auth/login/<provider-name>").
    app.MapIdentityProviderLogin(authProxyConfig.Authentication.GetAuthenticationScheme(identityProvider), authProxyConfig.Authentication.GetLoginPath(identityProvider));
}

// Map a global logout path.
app.MapLogout(authProxyConfig.Authentication.GetLogoutPath());

// Map everything else to YARP.
var handler = app.Services.GetRequiredService<YarpRequestHandler>();
app.Map("/{**catch-all}", handler.HandleRequest);

app.Run();