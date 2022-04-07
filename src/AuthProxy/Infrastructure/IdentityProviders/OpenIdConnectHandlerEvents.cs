using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure.IdentityProviders;

public class OpenIdConnectHandlerEvents : OpenIdConnectEvents
{
    private readonly IdentityProviderConfig identityProvider;
    private readonly ClaimsTransformer claimsTransformer;
    private readonly IDictionary<string, string> additionalParameters;
    private readonly IDictionary<string, string> additionalParametersForLogout;

    public OpenIdConnectHandlerEvents(IdentityProviderConfig identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.identityProvider = identityProvider;
        this.claimsTransformer = claimsTransformer;
        this.additionalParameters = this.identityProvider.AdditionalParameters.ParseKeyValuePairs(false);
        this.additionalParametersForLogout = this.identityProvider.AdditionalParametersForLogout.ParseKeyValuePairs(false);
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
        //context.Properties.IsPersistent = true; // Optionally ensure the session cookie is persistent across browser sessions.
    }
}