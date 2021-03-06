using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class BackendAppYarpHttpTransformer : BaseHttpTransformer
{
    private readonly AuthProxyConfig authProxyConfig;
    private readonly TokenIssuer tokenIssuer;

    public BackendAppYarpHttpTransformer(AuthProxyConfig authProxyConfig, TokenIssuer tokenIssuer)
    {
        this.authProxyConfig = authProxyConfig;
        this.tokenIssuer = tokenIssuer;
    }

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

        // Remove auth cookie in the request towards the app as it's internal to the proxy.
        RemoveCookie(proxyRequest, this.authProxyConfig.Authentication.Cookie.Name);

        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            // TODO: Token should be cached rather than recreated for each request.
            var backendAppIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.BackendApp);
            if (backendAppIdentity != null)
            {
                // TODO: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
                // For example: proxyRequest.Headers.Add("X-AuthProxy-Token", customPrefix + backendAppToken + customSuffix);
                var backendAppToken = this.tokenIssuer.CreateToken(backendAppIdentity);
                proxyRequest.Headers.Authorization = new AuthenticationHeaderValue(Constants.HttpHeaders.Bearer, backendAppToken);
                // TODO: Depending on configuration, forward individual (selected) claims as HTTP headers so the app doesn't even need to parse tokens.
            }
        }

        var roundTripIdentity = httpContext.User.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
        // TODO: Encrypt the information rather than package it up in a (signed but readable) JWT.
        // TODO: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
        var roundTripToken = this.tokenIssuer.CreateToken(roundTripIdentity, TokenIssuer.ApiAudience);
        proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackAuthorizationHeaderName, HeaderNames.Authorization);
        proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackAuthorizationHeaderValue, $"{Constants.HttpHeaders.Bearer} {roundTripToken}");

        // Inject headers containing the callback API paths to avoid that the backend app has to hard-code these.
        // TODO: Make configurable if and how to pass this information; for example a configuration setting with the HTTP header name,
        // in which case null or an empty string disables sending that information.
        proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackTokenEndpoint, this.authProxyConfig.Api.BasePath + "/" + Constants.ApiPaths.Token);
        proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackForwardEndpoint, this.authProxyConfig.Api.BasePath + "/" + Constants.ApiPaths.Forward);

        // Determine how to set the outgoing Host header.
        if (this.authProxyConfig.Backend.HostPolicy == HostPolicy.UseHostFromBackendApp)
        {
            proxyRequest.Headers.Host = null; // Suppress the original request header, use the one from the destination Uri.
        }
        else if (this.authProxyConfig.Backend.HostPolicy == HostPolicy.UseConfiguredHostName)
        {
            proxyRequest.Headers.Host = this.authProxyConfig.Backend.HostName; // Use the configured host name.
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
            var action = proxyResponse.Headers.GetValueOrDefault(AuthProxyConstants.HttpHeaderNames.Action);
            if (string.Equals(action, AuthProxyConstants.Actions.Logout, StringComparison.OrdinalIgnoreCase))
            {
                httpContext.Response.Clear();
                var returnUrl = proxyResponse.Headers.GetValueOrDefault(AuthProxyConstants.HttpHeaderNames.ReturnUrl) ?? "/";
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