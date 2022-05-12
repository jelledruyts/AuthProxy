using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;

// Don't map any standard OpenID Connect claims to Microsoft-specific claims
// so that the actual claim types sent by the proxy are shown on the pages.
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient();

builder.Services.AddRazorPages().AddRazorRuntimeCompilation();

// In case the reverse proxy is configured to overwrite the host header, ensure the app
// "sees" the original request URL by inspecting the headers added by the reverse proxy.
// See https://docs.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
});

// Add authentication based on the incoming JWT issued by the reverse proxy.
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = builder.Configuration.GetValue<string>("AuthProxy:BaseUrl"); // Refer back to Auth Proxy's OIDC metadata endpoint to validate incoming tokens.
        options.TokenValidationParameters.ValidAudience = "AuthProxy.BackendApp"; // The audience of the token is defined in Auth Proxy's configuration.
        options.TokenValidationParameters.NameClaimType = "name";
        options.TokenValidationParameters.RoleClaimType = "roles";
    });

var app = builder.Build();

app.UseExceptionHandler("/Error");
app.UseStaticFiles();
app.UseRouting();
app.UseForwardedHeaders();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

app.Run();