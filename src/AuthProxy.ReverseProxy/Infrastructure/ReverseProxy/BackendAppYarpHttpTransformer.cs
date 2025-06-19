using System.Net;
using System.Net.Http.Headers;
using System.Text;
using AuthProxy.ReverseProxy.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Net.Http.Headers;

namespace AuthProxy.ReverseProxy.Infrastructure.ReverseProxy;

public class BackendAppYarpHttpTransformer : BaseHttpTransformer
{
    private readonly AuthProxyConfig authProxyConfig;
    private readonly TokenIssuer tokenIssuer;

    public BackendAppYarpHttpTransformer(AuthProxyConfig authProxyConfig, TokenIssuer tokenIssuer)
    {
        this.authProxyConfig = authProxyConfig;
        this.tokenIssuer = tokenIssuer;
    }

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix, CancellationToken cancellationToken)
    {
        // Perform default behavior.
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

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

        // Remove the auth cookie in the request towards the app (as it's internal to the proxy)
        // and add it as a callback header so the backend app can use it to authenticate the USER back to the proxy.
        var authCookie = RemoveCookie(proxyRequest, this.authProxyConfig.Authentication.Cookie.Name);
        if (!string.IsNullOrWhiteSpace(authCookie))
        {
            proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackHeaderPrefix + HeaderNames.Cookie, authCookie);
        }

        // Create a round-trip token that can be used by the backend app to authenticate the BACKEND APP back to the proxy.
        // Although it would in theory be possible to use the authentication cookie ONLY for roundtrip
        // authentication, this has several disadvantages:
        // - The cookie is only present if there's an authenticated user, which is not always the case. Even without
        //   an authenticated user, the backend app may want to communicate back to the proxy.
        // - An end user (who can see the cookie) could use that same cookie to communicate directly with the proxy,
        //   rather than through the backend app, which may disclose information that should not be accessible to an end user.
        // Instead, we create a JWT issued by the proxy's internal token issuer, which is never sent back to the
        // browser but is only seen by the backend app.
        // TODO: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
        var roundTripIdentity = httpContext.User.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
        var roundTripToken = this.tokenIssuer.CreateToken(roundTripIdentity, TokenIssuer.ApiAudience);
        proxyRequest.Headers.Add(AuthProxyConstants.HttpHeaderNames.CallbackHeaderPrefix + HeaderNames.Authorization, $"{Constants.HttpHeaders.Bearer} {roundTripToken}");

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

    public override async ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse, CancellationToken cancellationToken)
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
        var shouldProxy = await base.TransformResponseAsync(httpContext, proxyResponse, cancellationToken);

        if (shouldProxy)
        {
            // Optionally add custom headers on the response back to the client.
            // This should generally be avoided though as the proxy is supposed to be transparent to the client.
        }
        return shouldProxy;
    }

    private static string RemoveCookie(HttpRequestMessage proxyRequest, string cookieNamePrefix)
    {
        // TODO: Add defensive coding to protect against maliciously formed cookie headers.
        // https://datatracker.ietf.org/doc/html/rfc6265#section-5.4
        const string CookieSeparator = "; ";
        var removedCookies = new StringBuilder();
        if (proxyRequest.Headers.Contains(HeaderNames.Cookie))
        {
            var newCookieHeader = new StringBuilder();
            // Get all cookie headers.
            foreach (var cookieHeader in proxyRequest.Headers.GetValues(HeaderNames.Cookie))
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
                    else
                    {
                        // If this is the cookie we need to remove, append it to the removed cookies.
                        if (removedCookies.Length > 0)
                        {
                            removedCookies.Append(CookieSeparator);
                        }
                        removedCookies.Append(cookie);
                    }
                }
            }

            // Remove all cookie headers.
            proxyRequest.Headers.Remove(HeaderNames.Cookie);

            // Add a new cookie header if there was any remaining cookie.
            if (newCookieHeader.Length > 0)
            {
                proxyRequest.Headers.Add(HeaderNames.Cookie, newCookieHeader.ToString());
            }
        }
        return removedCookies.ToString();
    }
}