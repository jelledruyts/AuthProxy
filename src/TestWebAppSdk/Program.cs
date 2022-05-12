using System.IdentityModel.Tokens.Jwt;
using AuthProxy.Client;

// Don't map any standard OpenID Connect claims to Microsoft-specific claims
// so that the actual claim types sent by the proxy are shown on the pages.
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthProxy(options =>
{
    builder.Configuration.Bind("AuthProxy", options);
});

builder.Services.AddRazorPages().AddRazorRuntimeCompilation();

var app = builder.Build();

app.UseExceptionHandler("/Error");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthProxy();
app.MapRazorPages();

app.Run();