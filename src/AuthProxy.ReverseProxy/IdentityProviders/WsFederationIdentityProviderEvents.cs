using AuthProxy.ReverseProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.WsFederation;

namespace AuthProxy.ReverseProxy.IdentityProviders;

public class WsFederationIdentityProviderEvents<TIdentityProvider> : WsFederationEvents where TIdentityProvider : IdentityProvider
{
    public TIdentityProvider IdentityProvider { get; }
    public ClaimsTransformer ClaimsTransformer { get; }
    public IDictionary<string, string> AdditionalParameters { get; }

    public WsFederationIdentityProviderEvents(TIdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimsTransformer = claimsTransformer;
        this.AdditionalParameters = this.IdentityProvider.Configuration.AdditionalParameters.ParseKeyValuePairs(false);
    }

    public override Task RedirectToIdentityProvider(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.AdditionalParameters);
        return Task.CompletedTask;
    }

    public async override Task SecurityTokenValidated(SecurityTokenValidatedContext context)
    {
        // Invoked when a token has been validated and produced an AuthenticationTicket.
        context.Principal = await this.ClaimsTransformer.TransformPrincipalAsync(context.Principal);
    }
}