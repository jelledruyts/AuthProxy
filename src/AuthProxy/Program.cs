using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Text.Json.Serialization;
using AuthProxy;
using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Infrastructure;
using AuthProxy.Infrastructure.ReverseProxy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

// Don't map any standard OpenID Connect claims to Microsoft-specific claims, let the claims transformer do that.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// Set up the web application and DI container.
var builder = WebApplication.CreateBuilder(args);

// Retrieve configuration.
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind("AuthProxy", authProxyConfig);
builder.Services.AddSingleton<AuthProxyConfig>(authProxyConfig);

// Construct the token issuer.
var tokenIssuer = new TokenIssuer(authProxyConfig);
builder.Services.AddSingleton<TokenIssuer>(tokenIssuer);

// Construct identity providers.
var identityProviderFactory = new IdentityProviderFactory(authProxyConfig);
builder.Services.AddSingleton<IdentityProviderFactory>(identityProviderFactory);

// Add YARP services.
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton<BackendAppYarpHttpTransformer>();
builder.Services.AddSingleton<BackendAppYarpRequestHandler>();
builder.Services.AddSingleton<ExternalServiceYarpHttpTransformer>();
builder.Services.AddSingleton<ExternalServiceYarpRequestHandler>();

// TODO: Set up ASP.NET Core Data Protection to share encryption keys etc across multiple instances.
// See https://docs.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview.

// Add cookie authentication as the final user session provider.
var authenticationBuilder = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme);
authenticationBuilder.AddCookie(options =>
{
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

// Add inbound authentication using the self-issued roundtrip JWT token sent to the backend app.
authenticationBuilder.AddJwtBearer(Constants.AuthenticationSchemes.AuthProxy, options =>
{
    // Trust JWT tokens that were issued from the local token issuer.
    options.TokenValidationParameters.ValidAudience = TokenIssuer.ApiAudience;
    options.TokenValidationParameters.ValidIssuer = tokenIssuer.Issuer;
    options.TokenValidationParameters.IssuerSigningKeys = tokenIssuer.SigningCredentials.Select(c => c.Key).ToArray();
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

// Map a login path per IdP (e.g. "/.auth/login/<id>").
foreach (var identityProvider in identityProviderFactory.IdentityProviders)
{
    app.Map(identityProvider.LoginPath, identityProvider.RequestLoginAsync);
}

// Map a global logout path.
var logoutPath = authProxyConfig.Authentication.LogoutPath;
var postLogoutReturnUrlQueryParameterName = authProxyConfig.Authentication.PostLogoutReturnUrlQueryParameterName;
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

// Map the "Forward" API to call an external service.
// TODO: Make configurable whether or not to enable this API as this increases the attack surface of the proxy.
var externalServicehandler = app.Services.GetRequiredService<ExternalServiceYarpRequestHandler>();
app.Map(authProxyConfig.Api.BasePath + "/" + Constants.ApiPaths.Forward, externalServicehandler.HandleRequest);

// Map everything else to YARP to be served by the backend app.
var backendAppHandler = app.Services.GetRequiredService<BackendAppYarpRequestHandler>();
app.Map("/{**catch-all}", backendAppHandler.HandleRequest);

app.Run();