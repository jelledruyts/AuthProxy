using Microsoft.AspNetCore.HttpLogging;
using Microsoft.AspNetCore.HttpOverrides;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorPages()
    .AddRazorRuntimeCompilation();
builder.Services.AddHttpLogging(options =>
{
    options.LoggingFields = HttpLoggingFields.RequestPropertiesAndHeaders;
});
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    // Ensure to disable the middleware that processes forwarded headers.
    // See https://docs.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer.
    options.ForwardedHeaders = ForwardedHeaders.None;
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseHttpLogging();
app.UseExceptionHandler("/Error");
app.UseStaticFiles();
app.UseRouting();
app.UseAuthorization();
app.MapRazorPages();

app.Run();
