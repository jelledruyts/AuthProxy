using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;

namespace AuthProxy.Client;

public static class AuthProxyApplicationBuilderExtensions
{
    public static IApplicationBuilder UseAuthProxy(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<AuthProxyOptions>();

        app.UseForwardedHeaders();
        if (options.AutoRedirectWhenRequired)
        {
            // Attach an exception handler that checks for the specific AuthProxyException
            // which is thrown when a redirect is required.
            app.UseExceptionHandler(new ExceptionHandlerOptions
            {
                ExceptionHandler = context =>
                {
                    // An exception occurred, get the exception handler feature to get the details.
                    var exceptionHandlerFeature = context.Features.Get<IExceptionHandlerFeature>();
                    var exception = exceptionHandlerFeature?.Error;
                    if (exception != null)
                    {
                        if (!(exception is AuthProxyTokenAcquisitionException authProxyException))
                        {
                            // Not the right type of exception, rethrow.
                            throw exception;
                        }

                        if (authProxyException.TokenResponse != null)
                        {
                            // Apply the token response to the HTTP response (redirecting if required).
                            authProxyException.TokenResponse.Apply(context.Response);
                        }
                    }
                    return Task.CompletedTask;
                }
            });
        }
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }
}