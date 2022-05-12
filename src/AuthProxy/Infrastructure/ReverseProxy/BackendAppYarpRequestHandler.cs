using AuthProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class BackendAppYarpRequestHandler : BaseYarpRequestHandler
{
    private readonly string backendAppUrl;
    private readonly IList<InboundPolicyConfig> inboundPolicies;

    public BackendAppYarpRequestHandler(ILogger<BackendAppYarpRequestHandler> logger, IHttpForwarder forwarder, AuthProxyConfig authProxyConfig, BackendAppYarpHttpTransformer transformer, TokenIssuer tokenIssuer)
        : base(logger, forwarder, transformer)
    {
        ArgumentNullException.ThrowIfNull(authProxyConfig.Backend.Url);
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
                if (httpContext.User.Identity?.IsAuthenticated == true)
                {
                    // The user is already authenticated, check if the policy requires specific IdPs.
                    if (inboundPolicy.IdentityProviders != null && inboundPolicy.IdentityProviders.Any())
                    {
                        var metadataIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.Metadata);
                        var idpNameClaim = metadataIdentity?.FindFirst(Constants.ClaimTypes.Metadata.IdentityProviderName);
                        if (idpNameClaim == null || !inboundPolicy.IdentityProviders.Contains(idpNameClaim.Value, StringComparer.OrdinalIgnoreCase))
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
                    // The user is not yet authenticated, trigger an authentication.
                    // If any IdPs were specified on the policy, use the first one to authenticate the user; otherwise use the default scheme.
                    var scheme = inboundPolicy.IdentityProviders?.FirstOrDefault() ?? Constants.AuthenticationSchemes.DefaultIdentityProvider;
                    return await ChallengeAsync(httpContext, scheme);
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