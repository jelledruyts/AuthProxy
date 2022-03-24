using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages()
    .AddRazorRuntimeCompilation();
builder.Services.AddHttpLogging(options =>
{
    options.LoggingFields = HttpLoggingFields.RequestPropertiesAndHeaders;
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    // Ensure to disable the middleware that processes forwarded headers to see the real headers.
    // See https://docs.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer.
    options.ForwardedHeaders = ForwardedHeaders.None;
});

JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters.ValidIssuer = "AuthProxy";
        options.TokenValidationParameters.ValidAudience = "AuthProxyBackendApp";
        // Skip checking of the signature.
        // TODO: Check against configured signing key of AuthProxy by having it expose OIDC metadata.
        options.TokenValidationParameters.SignatureValidator = (string token, TokenValidationParameters parameters) => new JwtSecurityToken(token);

        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "roles";
    });

var app = builder.Build();

app.UseForwardedHeaders();
app.UseHttpLogging();
app.UseExceptionHandler("/Error");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

app.Run();
