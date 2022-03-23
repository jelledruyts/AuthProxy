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
                options.ClaimActions.Clear(); // Don't remove any incoming claims.
                options.Authority = identityProvider.Authority;
                if (identityProvider.Scopes != null)
                {
                    foreach (var scope in identityProvider.Scopes)
                    {
                        options.Scope.Add(scope);
                    }
                }
                // options.Scope.Add(OpenIdConnectScope.OfflineAccess); // TODO: Only if needed, request a refresh token as part of the authorization code flow.

                options.TokenValidationParameters.ValidAudiences = identityProvider.AllowedAudiences;
                options.ClientId = identityProvider.ClientId;
                options.ClientSecret = identityProvider.ClientSecret;
                options.CallbackPath = loginCallbackPath; // The callback path must be unique per identity provider.

                options.Events.OnRedirectToIdentityProvider = (context) =>
                    {
                        // Pass through additional parameters if requested.
                        identityProvider.AdditionalParameters.CopyTo(context.ProtocolMessage.Parameters);
                        return Task.CompletedTask;
                    };

                options.Events.OnRedirectToIdentityProviderForSignOut = (context) =>
                {
                    // Pass through additional parameters if requested.
                    identityProvider.AdditionalParametersForLogout.CopyTo(context.ProtocolMessage.Parameters);
                    return Task.CompletedTask;
                };
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

    public static void MapIdentityProviderLogin(this IEndpointRouteBuilder endpoints, IdentityProviderConfig identityProvider, string authenticationScheme, string loginPath)
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

    public static void CopyTo(this string[]? values, IDictionary<string, string> target)
    {
        if (values != null)
        {
            foreach (var keyValue in values.Where(p => p != null))
            {
                var parts = keyValue.Split('=');
                if (parts.Length != 2)
                {
                    // TODO: Log
                }
                else
                {
                    var key = parts[0];
                    var value = parts[1];
                    target[key] = value;
                }
            }
        }
    }
}