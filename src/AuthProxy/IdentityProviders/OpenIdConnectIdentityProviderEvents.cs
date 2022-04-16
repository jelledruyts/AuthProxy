using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProviderEvents : OpenIdConnectEvents
{
    private readonly IdentityProvider identityProvider;
    private readonly ClaimsTransformer claimsTransformer;
    private readonly IDictionary<string, string> additionalParameters;
    private readonly IDictionary<string, string> additionalParametersForLogout;

    public OpenIdConnectIdentityProviderEvents(IdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.identityProvider = identityProvider;
        this.claimsTransformer = claimsTransformer;
        this.additionalParameters = this.identityProvider.Configuration.AdditionalParameters.ParseKeyValuePairs(false);
        this.additionalParametersForLogout = this.identityProvider.Configuration.AdditionalParametersForLogout.ParseKeyValuePairs(false);
    }

    public override Task RedirectToIdentityProvider(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.additionalParameters);
        return Task.CompletedTask;
    }

    public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
    {
        // Pass through additional parameters if requested.
        context.ProtocolMessage.Parameters.Merge(this.additionalParametersForLogout);
        return Task.CompletedTask;
    }

    public override Task TokenResponseReceived(TokenResponseReceivedContext context)
    {
        // Invoked after "authorization code" is redeemed for tokens at the token endpoint.
        // var identity = context.Principal?.Identity as ClaimsIdentity;
        return Task.CompletedTask;
    }

    public async override Task TokenValidated(TokenValidatedContext context)
    {
        // Invoked when an IdToken has been validated and produced an AuthenticationTicket.
        context.Principal = await this.claimsTransformer.TransformAsync(context.Principal);
    }
}