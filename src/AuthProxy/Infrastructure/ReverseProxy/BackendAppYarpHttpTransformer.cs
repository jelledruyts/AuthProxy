using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class BackendAppYarpHttpTransformer : BaseHttpTransformer
{
    private readonly string authProxyCookieName;
    private readonly HostPolicy backendHostPolicy;
    private readonly string? backendHostName;
    private readonly TokenIssuer tokenIssuer;

    public BackendAppYarpHttpTransformer(AuthProxyConfig authProxyConfig, TokenIssuer tokenIssuer)
    {
        this.authProxyCookieName = authProxyConfig.Authentication.Cookie.Name;
        this.backendHostPolicy = authProxyConfig.Backend.HostPolicy;
        this.backendHostName = authProxyConfig.Backend.HostName;
        this.tokenIssuer = tokenIssuer;
    }

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

        // Remove auth cookie in the request towards the app as it's internal to the proxy.
        RemoveCookie(proxyRequest, this.authProxyCookieName);

        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            // TODO: Token should be cached rather than recreated for each request.
            var backendAppIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.BackendApp);
            if (backendAppIdentity != null)
            {
                // TODO: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
                // For example: proxyRequest.Headers.Add("X-AuthProxy-Token", customPrefix + backendAppToken + customSuffix);
                var backendAppToken = this.tokenIssuer.CreateToken(backendAppIdentity);
                proxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", backendAppToken);
            }
        }

        var roundTripIdentity = httpContext.User.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
        // TODO: Encrypt the information rather than package it up in a (signed but readable) JWT.
        // TODO: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
        // TODO-M: Set "X-AuthProxy-API-Header-Name" and "X-AuthProxy-API-Header-Value" (including "Bearer") so that app needs to only echo that.
        var roundTripToken = this.tokenIssuer.CreateToken(roundTripIdentity, TokenIssuer.ApiAudience);
        proxyRequest.Headers.Add(Defaults.HeaderNameApiToken, roundTripToken);

        // Determine how to set the outgoing Host header.
        if (this.backendHostPolicy == HostPolicy.UseHostFromBackendApp)
        {
            proxyRequest.Headers.Host = null; // Suppress the original request header, use the one from the destination Uri.
        }
        else if (this.backendHostPolicy == HostPolicy.UseConfiguredHostName)
        {
            proxyRequest.Headers.Host = this.backendHostName; // Use the configured host name.
        }
        else
        {
            proxyRequest.Headers.Host = httpContext.Request.Host.Value; // Use the original request header.
        }
    }

    public override async ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse)
    {
        // The app can communicate back to the proxy with response HTTP headers, which can then take action.
        // Only do this if there is no logical better alternative, like a direct inbound URL from the app (e.g. "/.auth/logout").
        if (proxyResponse != null)
        {
            var action = proxyResponse.Headers.GetValueOrDefault(Defaults.HeaderNameAction);
            if (string.Equals(action, "logout", StringComparison.OrdinalIgnoreCase))
            {
                httpContext.Response.Clear();
                var returnUrl = proxyResponse.Headers.GetValueOrDefault(Defaults.HeaderNameReturnUrl) ?? "/";
                await httpContext.SignOutAsync(new AuthenticationProperties { RedirectUri = returnUrl });
                httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
                httpContext.Response.Headers.Location = returnUrl;
                return false;
            }
        }

        // Perform default behavior.
        var shouldProxy = await base.TransformResponseAsync(httpContext, proxyResponse);

        if (shouldProxy)
        {
            // Optionally add custom headers on the response back to the client.
            // This should generally be avoided though as the proxy is supposed to be transparent to the client.
        }
        return shouldProxy;
    }

    private static void RemoveCookie(HttpRequestMessage proxyRequest, string cookieNamePrefix)
    {
        // TODO: Add defensive coding to protect against maliciously formed cookie headers.
        // https://datatracker.ietf.org/doc/html/rfc6265#section-5.4
        const string CookieHeaderName = "Cookie";
        const string CookieSeparator = "; ";
        if (proxyRequest.Headers.Contains(CookieHeaderName))
        {
            var newCookieHeader = new StringBuilder();
            // Get all cookie headers.
            foreach (var cookieHeader in proxyRequest.Headers.GetValues(CookieHeaderName))
            {
                // Split by the separator (as per specification).
                foreach (var cookie in cookieHeader.Split(CookieSeparator))
                {
                    // Append the cookie if it's not the one we need to strip out.
                    if (!cookie.StartsWith(cookieNamePrefix))
                    {
                        if (newCookieHeader.Length > 0)
                        {
                            newCookieHeader.Append(CookieSeparator);
                        }
                        newCookieHeader.Append(cookie);
                    }
                }
            }

            // Remove all cookie headers.
            proxyRequest.Headers.Remove(CookieHeaderName);

            // Add a new cookie header if there was any remaining cookie.
            if (newCookieHeader.Length > 0)
            {
                proxyRequest.Headers.Add(CookieHeaderName, newCookieHeader.ToString());
            }
        }
    }
}