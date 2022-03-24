using System.Diagnostics;
using System.Net;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure;

public static class ExtensionMethods
{
    public static void AddIdentityProvider(this AuthenticationBuilder authenticationBuilder, IdentityProviderConfig identityProvider, string authenticationScheme, string loginCallbackPath)
    {
        if (identityProvider.Type == IdentityProviderType.OpenIdConnect)
        {
            authenticationBuilder.AddOpenIdConnect(authenticationScheme, options =>
            {
                new OpenIdConnectHandler(identityProvider, options, loginCallbackPath);
            });
        }
        // else if (authProxyConfig.Authentication.IdentityProvider.Type == IdentityProviderType.JwtBearer)
        // {
        //     authenticationBuilder.AddJwtBearer(options =>
        //     {
        //         // TODO: Make configurable where the incoming JWT is found (for example, use a different HTTP header).
        //         // https://stackoverflow.com/questions/56857905/how-to-customize-bearer-header-keyword-in-asp-net-core-for-jwtbearer-and-system
        //         options.Authority = authProxyConfig.Authentication.IdentityProvider.Authority;
        //     });
        // }
    }

    public static void MapIdentityProviderLogin(this IEndpointRouteBuilder endpoints, string authenticationScheme, string loginPath)
    {
        // TODO: Log the path being mapped.
        endpoints.Map(loginPath, async httpContext =>
        {
            // TODO: Capture and process "return URL" from "post_login_redirect_uri" (or configurable query parameter).
            var returnUrl = "/";
            if (httpContext.User.Identity?.IsAuthenticated != true)
            {
                // The user isn't logged in, redirect to the identity provider and capture the return URL.
                await httpContext.ChallengeAsync(authenticationScheme, new AuthenticationProperties { RedirectUri = returnUrl });
            }
            else
            {
                // The user is already logged in, redirect straight back to the requested URL.
                httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
                httpContext.Response.Headers.Location = returnUrl;
            }
        });
    }

    public static void MapLogout(this IEndpointRouteBuilder endpoints, string logoutPath)
    {
        endpoints.Map(logoutPath, async httpContext =>
        {
            // TODO: Capture and process "return URL" from "post_logout_redirect_uri" (or configurable query parameter).
            var returnUrl = "/";
            if (httpContext.User.Identity?.IsAuthenticated == true)
            {
                // TODO: If configured, also trigger Single Sign-Out across all authenticated IdPs.
                await httpContext.SignOutAsync(new AuthenticationProperties { RedirectUri = returnUrl });
            }
            httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
            httpContext.Response.Headers.Location = returnUrl;
        });
    }

    public static void MapReverseProxy(this WebApplication app, AuthProxyConfig authProxyConfig)
    {
        var forwarder = app.Services.GetRequiredService<IHttpForwarder>();
        var httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
        });

        var defaultTransformer = HttpTransformer.Default;
        var customTransformer = new YarpHttpTransformer(authProxyConfig.Authentication!.Cookie!.Name!, new TokenIssuer(authProxyConfig.Authentication!.TokenIssuer!.Audience!, authProxyConfig.Authentication!.TokenIssuer!.Issuer!, authProxyConfig.Authentication!.TokenIssuer!.Expiration!.Value, authProxyConfig.Authentication!.TokenIssuer!.SigningSecret!));
        var requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };

        // Map any other request to the backend app.
        app.Map("/{**catch-all}", async httpContext =>
        {
            // if (httpContext.User.Identity?.IsAuthenticated != true)
            // {
            //     // TODO: Don't *always* authenticate, should be configurable based on path or other conditions.
            //     await httpContext.ChallengeAsync(scheme);
            // }
            // else
            {
                // Forward the incoming request to the backend app.
                var error = await forwarder.SendAsync(httpContext, authProxyConfig.Backend!.Url!, httpClient, requestOptions, customTransformer);
                if (error != ForwarderError.None)
                {
                    var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                    var exception = errorFeature?.Exception;
                    // TODO: Log
                }
            }
        });
    }

    public static IDictionary<string, string> ParseKeyValuePairs(this IEnumerable<string?>? keyValuePairs, bool allowShorthandForm)
    {
        var result = new Dictionary<string, string>();
        if (keyValuePairs != null)
        {
            foreach (var keyValue in keyValuePairs.Where(p => p != null))
            {
                var parts = keyValue!.Split('=', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var key = parts[0];
                if (parts.Length == 1 && allowShorthandForm)
                {
                    // The value "<key>" is short hand syntax for "<key>=<key>".
                    result[key] = key;
                }
                else if (parts.Length != 2)
                {
                    throw new ArgumentException($"Could not parse key/value pair: \"keyValue\".", nameof(keyValuePairs));
                }
                else
                {
                    result[key] = parts[1];
                }
            }
        }
        return result;
    }

    public static void Merge(this IDictionary<string, string> target, IDictionary<string, string> source)
    {
        source.ToList().ForEach(x => target[x.Key] = x.Value);
    }
}