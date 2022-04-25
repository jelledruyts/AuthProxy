using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure;

public class YarpHttpTransformer : HttpTransformer
{
    private readonly string authProxyCookieName;
    private readonly TokenIssuer tokenIssuer;

    public YarpHttpTransformer(string authProxyCookieName, TokenIssuer tokenIssuer)
    {
        this.authProxyCookieName = authProxyCookieName;
        this.tokenIssuer = tokenIssuer;
    }

    /// <summary>
    /// A callback that is invoked prior to sending the proxied request. All HttpRequestMessage fields are
    /// initialized except RequestUri, which will be initialized after the callback if no value is provided.
    /// See <see cref="RequestUtilities.MakeDestinationAddress(string, PathString, QueryString)"/> for constructing a custom request Uri.
    /// The string parameter represents the destination URI prefix that should be used when constructing the RequestUri.
    /// The headers are copied by the base implementation, excluding some protocol headers like HTTP/2 pseudo headers (":authority").
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyRequest">The outgoing proxy request.</param>
    /// <param name="destinationPrefix">The uri prefix for the selected destination server which can be used to create the RequestUri.</param>
    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await HttpTransformer.Default.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

        // Remove auth cookie in the request towards the app as it's internal to the proxy.
        RemoveCookie(proxyRequest, this.authProxyCookieName);

        if (httpContext.User.Identity?.IsAuthenticated == true)
        {
            // TODO-L: Token should be cached rather than recreated for each request.
            var backendAppIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.BackendApp);
            if (backendAppIdentity != null)
            {
                // TODO-C: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
                // For example: proxyRequest.Headers.Add("X-Auth-Token", customPrefix + backendAppToken + customSuffix);
                var backendAppToken = this.tokenIssuer.CreateToken(backendAppIdentity.Claims);
                proxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", backendAppToken);
            }
        }

        var roundTripIdentity = httpContext.User.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
        // TODO-M: Encrypt the information rather than package it up in a (signed but readable) JWT.
        // TODO-C: Make configurable if and how to pass the token to the app; could also be disabled or in custom header with custom format.
        var roundTripToken = this.tokenIssuer.CreateToken(roundTripIdentity.Claims);
        proxyRequest.Headers.Add("X-AuthProxy-API-token", roundTripToken);

        // TODO-C: Make configurable.
        proxyRequest.Headers.Host = httpContext.Request.Host.Value; // Use the original request header.
        // proxyRequest.Headers.Host = null; // Suppress the original request header, use the one from the destination Uri.
    }

    /// <summary>
    /// A callback that is invoked when the proxied response is received. The status code and reason phrase will be copied
    /// to the HttpContext.Response before the callback is invoked, but may still be modified there. The headers will be
    /// copied to HttpContext.Response.Headers by the base implementation, excludes certain protocol headers like
    /// `Transfer-Encoding: chunked`.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination. This can be null if the destination did not respond.</param>
    /// <returns>A bool indicating if the response should be proxied to the client or not. A derived implementation 
    /// that returns false may send an alternate response inline or return control to the caller for it to retry, respond, 
    /// etc.</returns>
    public override async ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse)
    {
        // The app can communicate back to the proxy with response HTTP headers, which can then take action.
        // Only do this if there is no logical better alternative, like a direct inbound URL from the app (e.g. "/.auth/logout").
        if (proxyResponse != null && proxyResponse.Headers.Contains("X-Auth-Action"))
        {
            var action = proxyResponse.Headers.GetValues("X-Auth-Action").First();
            httpContext.Response.Clear();
            if (action == "logout")
            {
                var returnUrl = "/";
                await httpContext.SignOutAsync(new AuthenticationProperties { RedirectUri = returnUrl });
                httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
                httpContext.Response.Headers.Location = returnUrl;
            }
            return false;
        }
        // Perform default behavior.
        var shouldProxy = await HttpTransformer.Default.TransformResponseAsync(httpContext, proxyResponse);

        if (shouldProxy)
        {
            // Add custom headers on the response back to the client.
            // This should generally be avoided though as the proxy is supposed to be transparent to the client.
            // httpContext.Response.Headers.Add("X-Auth-Response", "OK");
        }
        return shouldProxy;
    }

    /// <summary>
    /// A callback that is invoked after the response body to modify trailers, if supported. The trailers will be
    /// copied to the HttpContext.Response by the base implementation.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination.</param>
    public override ValueTask TransformResponseTrailersAsync(HttpContext httpContext, HttpResponseMessage proxyResponse)
    {
        // Perform default behavior.
        return HttpTransformer.Default.TransformResponseTrailersAsync(httpContext, proxyResponse);
    }

    private static void RemoveCookie(HttpRequestMessage proxyRequest, string cookieNamePrefix)
    {
        // TODO-L: Add defensive coding to protect against maliciously formed cookie headers.
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