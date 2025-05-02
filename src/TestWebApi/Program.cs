using System.IdentityModel.Tokens.Jwt;
using AuthProxy.Client;

// Don't map any standard OpenID Connect claims to Microsoft-specific claims
// so that the actual claim types sent by the proxy are shown on the pages.
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddAuthProxy(options =>
{
    builder.Configuration.Bind("AuthProxy", options);
});

var app = builder.Build();

app.UseAuthProxy();
app.MapControllers();

app.Run();