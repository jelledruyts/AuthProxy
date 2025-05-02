using System.Net;
using AuthProxy.Models;
using Microsoft.AspNetCore.Http;

namespace AuthProxy.Client;

public static class HttpResponseExtensions
{
    public static bool Apply(this TokenResponse tokenResponse, HttpResponse response)
    {
        if (tokenResponse.Status == TokenResponseStatus.RedirectRequired)
        {
            if (tokenResponse.RedirectUrl != null)
            {
                if (tokenResponse.RedirectCookies != null)
                {
                    response.Headers.SetCookie = tokenResponse.RedirectCookies.ToArray();
                }
                response.Redirect(tokenResponse.RedirectUrl);

                // Signal to the caller that the response has been set based on the token response
                // and that further processing should be stopped.
                return false;
            }
        }

        // No action to take, let the caller proceed as usual.
        return true;
    }

    public static TokenResponse? ToTokenResponse(this HttpResponseMessage response)
    {
        // The proxy sets the "511 Network Authentication Required" status code if it could not complete the request.
        if (response.StatusCode == HttpStatusCode.NetworkAuthenticationRequired)
        {
            // The request could not be forwarded, check response headers for status.
            if (response.Headers.Contains(AuthProxyConstants.HttpHeaderNames.Status))
            {
                return new TokenResponse
                {
                    Status = Enum.Parse<TokenResponseStatus>(response.Headers.GetValues(AuthProxyConstants.HttpHeaderNames.Status).First()),
                    RedirectUrl = response.Headers.GetValues(AuthProxyConstants.HttpHeaderNames.RedirectUrl).FirstOrDefault(),
                    RedirectCookies = response.Headers.GetValues(AuthProxyConstants.HttpHeaderNames.RedirectCookies).ToArray()
                };
            }
        }
        return null;
    }

    public static void SignalAuthProxyLogout(this HttpResponse response)
    {
        response.SignalAuthProxyLogout(null);
    }

    public static void SignalAuthProxyLogout(this HttpResponse response, string? returnUrl)
    {
        response.SignalAuthProxyAction(AuthProxyConstants.Actions.Logout);
        if (returnUrl != null)
        {
            response.Headers.Append(AuthProxyConstants.HttpHeaderNames.ReturnUrl, returnUrl);
        }
    }

    public static void SignalAuthProxyAction(this HttpResponse response, string action)
    {
        response.Headers.Append(AuthProxyConstants.HttpHeaderNames.Action, action);
    }
}