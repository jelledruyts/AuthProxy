using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class BackendAppYarpRequestHandler : BaseYarpRequestHandler
{
    private readonly IdentityProviderFactory identityProviderFactory;
    private readonly string backendAppUrl;
    private readonly IList<InboundPolicyConfig> inboundPolicies;

    public BackendAppYarpRequestHandler(ILogger<BackendAppYarpRequestHandler> logger, IHttpForwarder forwarder, AuthProxyConfig authProxyConfig, BackendAppYarpHttpTransformer transformer, TokenIssuer tokenIssuer, IdentityProviderFactory identityProviderFactory)
        : base(logger, forwarder, transformer)
    {
        ArgumentNullException.ThrowIfNull(authProxyConfig.Backend.Url);
        this.identityProviderFactory = identityProviderFactory;
        this.backendAppUrl = authProxyConfig.Backend.Url;
        this.inboundPolicies = authProxyConfig.Policies.Inbound;
    }

    protected override async Task<bool> ShouldForwardRequestAsync(HttpContext httpContext)
    {
        // Check if there is a matching inbound policy.
        var inboundPolicy = GetMatchingInboundPolicy(httpContext.Request);
        if (inboundPolicy != null)
        {
            // An inbound policy applies to the request, check the required action.
            if (inboundPolicy.Action == InboundPolicyAction.Authenticate)
            {
                // Authentication is required, check if the user is already authenticated.

                // Determine the IdPs as specified on the policy, or the default IdP otherwise.
                var identityProviders = this.identityProviderFactory.GetIdentityProviders(inboundPolicy.IdentityProviders);
                if (!identityProviders.Any() && this.identityProviderFactory.DefaultIdentityProvider != null)
                {
                    identityProviders.Add(this.identityProviderFactory.DefaultIdentityProvider);
                }

                if (httpContext.User.Identity?.IsAuthenticated != true)
                {
                    // The user isn't authenticated yet, but possibly a participating IdP can authenticate the user ad hoc
                    // (for example, by inspecting an incoming JWT bearer token).
                    foreach (var identityProvider in identityProviders)
                    {
                        if (await identityProvider.AttemptAuthenticateAsync(httpContext))
                        {
                            break;
                        }
                    }
                }

                if (httpContext.User.Identity?.IsAuthenticated == true)
                {
                    // The user is already authenticated, check if the policy requires specific IdPs.
                    if (inboundPolicy.IdentityProviders != null && inboundPolicy.IdentityProviders.Any())
                    {
                        var metadataIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.Metadata);
                        var idpIdClaim = metadataIdentity?.FindFirst(Constants.ClaimTypes.Metadata.IdentityProviderId);
                        if (idpIdClaim == null || !inboundPolicy.IdentityProviders.Contains(idpIdClaim.Value, StringComparer.OrdinalIgnoreCase))
                        {
                            // The user was authenticated but NOT with one of the allowed IdPs specified on the policy.
                            // TODO: Allow configuration to decide what to do when authenticated but not with a matching IdP:
                            // either force authentication to an explicitly specified IdP or deny the request.
                            return await ForbiddenAsync(httpContext);
                        }
                    }
                }
                else
                {
                    // The user is not yet authenticated, trigger an authentication from the first configured (or default) IdP.
                    await identityProviders.First().ChallengeAsync(httpContext);
                    return false;
                }
            }
            else if (inboundPolicy.Action == InboundPolicyAction.Deny)
            {
                // The request is explicitly denied.
                return await ForbiddenAsync(httpContext);
            }
        }

        // No matching inbound policy or no reason to deny the request, forward to backend app.
        return true;
    }

    protected override string? GetDestinationPrefix(HttpContext httpContext)
    {
        return this.backendAppUrl;
    }

    private InboundPolicyConfig? GetMatchingInboundPolicy(HttpRequest request)
    {
        foreach (var inboundPolicy in this.inboundPolicies)
        {
            // TODO: Support more than a simple "starts with" match on the path pattern.
            if (inboundPolicy.PathPatterns != null && inboundPolicy.PathPatterns.Any(p => request.Path.StartsWithSegments(new PathString(p), StringComparison.InvariantCultureIgnoreCase)))
            {
                // Stop processing more policies when a match was found.
                return inboundPolicy;
            }
        }
        return null;
    }
}