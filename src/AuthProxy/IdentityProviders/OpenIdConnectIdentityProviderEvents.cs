using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProviderEvents<TIdentityProvider> : OpenIdConnectEvents where TIdentityProvider : IdentityProvider
{
    public TIdentityProvider IdentityProvider { get; }
    public ClaimsTransformer ClaimsTransformer { get; }
    public IDictionary<string, string> AdditionalParameters { get; }
    public IDictionary<string, string> AdditionalParametersForLogout { get; }

    public OpenIdConnectIdentityProviderEvents(TIdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimsTransformer = claimsTransformer;
        this.AdditionalParameters = this.IdentityProvider.Configuration.AdditionalParameters.ParseKeyValuePairs(false);
        this.AdditionalParametersForLogout = this.IdentityProvider.Configuration.AdditionalParametersForLogout.ParseKeyValuePairs(false);
    }

    public override Task RedirectToIdentityProvider(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.AdditionalParameters);
        return Task.CompletedTask;
    }

    public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.AdditionalParametersForLogout);
        return Task.CompletedTask;
    }

    public async override Task TokenValidated(TokenValidatedContext context)
    {
        // Invoked when an IdToken has been validated and produced an AuthenticationTicket.
        context.Principal = await this.ClaimsTransformer.TransformPrincipalAsync(context.Principal);
    }
}