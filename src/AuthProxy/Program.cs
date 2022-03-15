using AuthProxy.Configuration;

var builder = WebApplication.CreateBuilder(args);
var authProxyConfig = new AuthProxyConfig();
builder.Configuration.Bind(AuthProxyConfig.ConfigSectionName, authProxyConfig);
builder.AddYarp(authProxyConfig);
var app = builder.Build();
app.MapReverseProxy();

app.Run();
