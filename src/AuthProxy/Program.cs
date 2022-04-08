using System.IdentityModel.Tokens.Jwt;
using AuthProxy.Configuration;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind("AuthProxy", authProxyConfig);
builder.Services.AddSingleton<AuthProxyConfig>(authProxyConfig);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.IdentityProviders);
ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.Cookie);
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
    options.Cookie.Name = authProxyConfig.Authentication.Cookie.Name;
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
    ArgumentNullException.ThrowIfNull(identityProvider.Name);
    // TODO: Ensure IdentityProvider's Name is acceptable in URLs, unique across other IdPs and does not conflict with the default authentication scheme (Defaults.AuthenticationScheme)
    // TODO: Ensure IdentityProvider's callback paths are unique across all configured IdPs and don't conflict with the default paths.
    authenticationBuilder.AddIdentityProvider(identityProvider, identityProvider.Name, authProxyConfig.Authentication.GetLoginCallbackPath(identityProvider));
}

var app = builder.Build();

// Configure authentication.
app.UseAuthentication();

// Map login paths for identity providers.
var postLoginReturnUrlQueryParameterName = Defaults.PostLoginReturnUrlQueryParameterName; // TODO: Make configurable.
if (defaultIdentityProvider != null)
{
    // Map a login path for the default IdP (e.g. "/.auth/login").
    app.MapIdentityProviderLogin(authProxyConfig.Authentication.GetDefaultAuthenticationScheme(), authProxyConfig.Authentication.GetDefaultLoginPath(), postLoginReturnUrlQueryParameterName);
}
foreach (var identityProvider in authProxyConfig.Authentication.IdentityProviders)
{
    // Map a login path per IdP (e.g. "/.auth/login/<provider-name>").
    ArgumentNullException.ThrowIfNull(identityProvider.Name);
    app.MapIdentityProviderLogin(identityProvider.Name, authProxyConfig.Authentication.GetLoginPath(identityProvider), postLoginReturnUrlQueryParameterName);
}

// Map a global logout path.
var postLogoutReturnUrlQueryParameterName = Defaults.PostLogoutReturnUrlQueryParameterName; // TODO: Make configurable.
app.MapLogout(authProxyConfig.Authentication.GetLogoutPath(), postLogoutReturnUrlQueryParameterName);

// Map everything else to YARP.
var handler = app.Services.GetRequiredService<YarpRequestHandler>();
app.Map("/{**catch-all}", handler.HandleRequest);

app.Run();