using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json.Serialization;
using AuthProxy;
using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind("AuthProxy", authProxyConfig);
builder.Services.AddSingleton<AuthProxyConfig>(authProxyConfig);

// Construct identity providers.
var identityProviderFactory = new IdentityProviderFactory(authProxyConfig);
builder.Services.AddSingleton<IdentityProviderFactory>(identityProviderFactory);

// Add YARP services.
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton<YarpRequestHandler>();

// TODO-L: Set up ASP.NET Core Data Protection to share encryption keys etc across multiple instances.
// See https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview.

// Add authentication services.
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.

// Add cookie authentication as the final user session provider.
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
authenticationBuilder.AddCookie(options =>
{
    // TODO-L: Also rename other cookies (.AspNetCore.* for correlation and nonce for example)
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

// Add inbound authentication using the self-issued JWT token sent to the backend app.
authenticationBuilder.AddJwtBearer(Constants.AuthenticationSchemes.AuthProxy, options =>
{
    options.TokenValidationParameters.ValidIssuer = authProxyConfig.Authentication.TokenIssuer.Issuer;
    options.TokenValidationParameters.ValidAudience = authProxyConfig.Authentication.TokenIssuer.Audience;
    // TODO-M: Check against configured signing key of AuthProxy itself.
    options.TokenValidationParameters.SignatureValidator = (string token, TokenValidationParameters parameters) => new JwtSecurityToken(token);
});

// Add an authentication service for each IdP.
foreach (var identityProvider in identityProviderFactory.IdentityProviders)
{
    identityProvider.AddAuthentication(authenticationBuilder);
}

builder.Services.AddControllers()
    .AddMvcOptions(options =>
    {
        options.Conventions.Add(new ApiRoutingConvention(authProxyConfig.Api.BasePath));
    })
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });
builder.Services.AddRouting(options => { options.LowercaseUrls = true; });

var app = builder.Build();

// Configure authentication and authorization.
app.UseAuthentication();
app.UseAuthorization();

// Map API controllers.
app.MapControllers();

// Map a login path per IdP (e.g. "/.auth/login/<name>").
foreach (var identityProvider in identityProviderFactory.IdentityProviders)
{
    app.Map(identityProvider.LoginPath, identityProvider.RequestLoginAsync);
}

// Map a global logout path.
var logoutPath = Defaults.LogoutPath; // TODO-C: Make this configurable.
var postLogoutReturnUrlQueryParameterName = Defaults.PostLogoutReturnUrlQueryParameterName; // TODO-C: Make configurable.
app.Map(logoutPath, async httpContext =>
{
    var returnUrl = "/";
    if (httpContext.Request.Query.TryGetValue(postLogoutReturnUrlQueryParameterName, out var postLogoutReturnUrlValue))
    {
        returnUrl = postLogoutReturnUrlValue.First();
    }
    if (httpContext.User.Identity?.IsAuthenticated == true)
    {
        // TODO-L: If configured, also trigger Single Sign-Out across all authenticated IdPs.
        await httpContext.SignOutAsync(new AuthenticationProperties { RedirectUri = returnUrl });
    }
    httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
    httpContext.Response.Headers.Location = returnUrl;
});

// Map everything else to YARP.
var handler = app.Services.GetRequiredService<YarpRequestHandler>();
app.Map("/{**catch-all}", handler.HandleRequest);

app.Run();