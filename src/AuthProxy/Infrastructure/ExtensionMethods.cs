using System.Net;
using AuthProxy.Configuration;
using AuthProxy.Infrastructure.IdentityProviders;
using Microsoft.AspNetCore.Authentication;

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
        else if (identityProvider.Type == IdentityProviderType.AzureAD)
        {
            authenticationBuilder.AddOpenIdConnect(authenticationScheme, options =>
            {
                new AzureADHandler(identityProvider, options, loginCallbackPath);
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
        else
        {
            throw new ArgumentOutOfRangeException(nameof(identityProvider.Type), $"Unknown {nameof(IdentityProviderType)}: \"{identityProvider.Type.ToString()}\".");
        }
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