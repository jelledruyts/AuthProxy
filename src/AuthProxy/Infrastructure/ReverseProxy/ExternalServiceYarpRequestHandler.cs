using System.Net;
using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Primitives;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class ExternalServiceYarpRequestHandler : BaseYarpRequestHandler
{
    private readonly IdentityProviderFactory identityProviderFactory;
    private readonly AuthProxyConfig authProxyConfig;

    public ExternalServiceYarpRequestHandler(ILogger<ExternalServiceYarpRequestHandler> logger, IHttpForwarder forwarder, ExternalServiceYarpHttpTransformer transformer, IdentityProviderFactory identityProviderFactory, AuthProxyConfig authProxyConfig)
        : base(logger, forwarder, transformer)
    {
        this.identityProviderFactory = identityProviderFactory;
        this.authProxyConfig = authProxyConfig;
    }

    protected override async Task<bool> ShouldForwardRequestAsync(HttpContext httpContext)
    {
        // This is a reverse proxy request for an external service, authenticate a principal from the expected incoming API token.
        var authenticateResult = await httpContext.AuthenticateAsync(Constants.AuthenticationSchemes.AuthProxy);
        if (authenticateResult.Principal?.Identity == null || !authenticateResult.Principal.Identity.IsAuthenticated)
        {
            // This is an unauthenticated API call, reject the request.
            return await ForbiddenAsync(httpContext);
        }
        httpContext.User = authenticateResult.Principal;

        // Get the destination header from the incoming request header.
        var destinationUrl = httpContext.Request.Headers.GetValueOrDefault(Defaults.HeaderNameDestination);
        httpContext.Request.Headers.Remove(Defaults.HeaderNameDestination); // Remove the header from the outgoing request.
        if (destinationUrl == null)
        {
            // No destination URL was requested, reject the request.
            return await ForbiddenAsync(httpContext);
        }
        httpContext.Items[ExternalServiceYarpHttpTransformer.ContextItemKeyRequestUri] = new Uri(destinationUrl);

        // Look for a matching outbound policy.
        var outboundPolicy = GetMatchingOutboundPolicy(destinationUrl);
        if (outboundPolicy == null || outboundPolicy.TokenRequestProfile == null)
        {
            // No outbound policy matched the requested destination URL, simply forward the request without further processing.
            this.Logger.LogWarning($"An outbound call to \"{destinationUrl}\" was requested but has no matching outbound policy configured.");
            return true;
        }
        var profile = this.authProxyConfig.Authentication.TokenRequestProfiles.FirstOrDefault(p => string.Equals(p.Name, outboundPolicy.TokenRequestProfile, StringComparison.OrdinalIgnoreCase));
        if (profile == null)
        {
            // No token request profile was configured on the outbound policy, simply forward the request without further processing.
            this.Logger.LogWarning($"An outbound call to \"{destinationUrl}\" was requested but the matching outbound policy had no token request profile configured.");
            return true;
        }
        var identityProvider = this.identityProviderFactory.GetIdentityProvider(profile.IdentityProvider);
        if (identityProvider == null)
        {
            // No identity provider was configured on the token request profile, simply forward the request without further processing.
            this.Logger.LogWarning($"An outbound call to \"{destinationUrl}\" was requested but the matching outbound policy's token request profile had no identity provider configured.");
            return true;
        }

        // Request a token from the identity provider.
        var returnUrl = httpContext.Request.Headers.GetValueOrDefault(Defaults.HeaderNameReturnUrl);
        httpContext.Request.Headers.Remove(Defaults.HeaderNameReturnUrl); // Remove the header from the outgoing request.
        var token = await identityProvider.GetTokenAsync(httpContext, new TokenRequest
        {
            Actor = profile.Actor,
            Scopes = profile.Scopes,
            ReturnUrl = returnUrl ?? profile.ReturnUrl ?? "/"
        });

        if (token.Status == TokenResponseStatus.Succeeded)
        {
            // The required token was acquired, pass information to the HTTP transformer to include it on the outbound call.
            httpContext.Items[ExternalServiceYarpHttpTransformer.ContextItemKeyOutboundPolicyAction] = outboundPolicy.Action;
            httpContext.Items[ExternalServiceYarpHttpTransformer.ContextItemKeyToken] = token.Token;
            return true;
        }
        else if (token.Status == TokenResponseStatus.RedirectRequired)
        {
            // The required token could not be acquired and a redirect is required, return redirect information back to caller via
            // HTTP response headers (as the response body is expected to match whatever the external service would have returned).
            httpContext.Response.StatusCode = (int)HttpStatusCode.NetworkAuthenticationRequired;
            httpContext.Response.Headers.Add(Defaults.HeaderNameStatus, token.Status.ToString());
            httpContext.Response.Headers.Add(Defaults.HeaderNameRedirectUrl, token.RedirectUrl);
            if (token.RedirectCookies != null && token.RedirectCookies.Any())
            {
                httpContext.Response.Headers.Add(Defaults.HeaderNameRedirectCookies, (StringValues)token.RedirectCookies);
            }
            await httpContext.Response.CompleteAsync();
            return false;
        }
        else
        {
            // A token was required by the outbound policy but could not be acquired, error out.
            throw new ApplicationException($"An outbound call to \"{destinationUrl}\" required a token but it could not be acquired; token request status: \"{token.Status.ToString()}\".");
        }
    }

    private OutboundPolicyConfig? GetMatchingOutboundPolicy(string destinationUrl)
    {
        foreach (var outboundPolicy in this.authProxyConfig.Policies.Outbound)
        {
            // TODO: Support more than a simple "starts with" match on the path pattern.
            if (outboundPolicy.UrlPattern != null && destinationUrl.StartsWith(outboundPolicy.UrlPattern, StringComparison.InvariantCultureIgnoreCase))
            {
                // Stop processing more policies when a match was found.
                return outboundPolicy;
            }
        }
        return null;
    }
}