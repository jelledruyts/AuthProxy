using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();
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

    // On the other hand, *if* the reverse proxy is configured to overwrite the host header,
    // ensure the app "sees" the original request URL by inspecting the headers added by the reverse proxy.
    // options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
});

JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear(); // Don't map any standard OpenID Connect claims to Microsoft-specific claims.

// Add authentication based on the incoming JWT issued by the reverse proxy.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "https://localhost:7268"; // Refer back to Auth Proxy's OIDC metadata endpoint to validate incoming tokens.
        options.TokenValidationParameters.ValidAudience = "AuthProxy.BackendApp"; // The audience of the token is defined in Auth Proxy's configuration.
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
