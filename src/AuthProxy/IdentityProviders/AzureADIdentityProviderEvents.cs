using System.Security.Claims;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class AzureADIdentityProviderEvents : OpenIdConnectIdentityProviderEvents<AzureADIdentityProvider>
{
    public AzureADIdentityProviderEvents(AzureADIdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
        : base(identityProvider, claimsTransformer)
    {
    }

    public override async Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        await base.AuthorizationCodeReceived(context);

        // Use the MSAL token provider to redeem the authorization code for an ID token, access token and refresh token.
        // These aren't used here directly (except the ID token) but they are added to the MSAL cache for later use.
        var result = await this.IdentityProvider.RedeemAuthorizationCodeAsync(context.HttpContext, context.ProtocolMessage.Code);

        // Remember the MSAL home account identifier so it can be stored in the claims later on.
        context.Properties ??= new AuthenticationProperties();
        context.Properties.SetParameter(AzureADIdentityProvider.ClaimTypeHomeAccountId, result.Account.HomeAccountId.Identifier);

        // Signal to the OpenID Connect middleware that the authorization code is already redeemed and it should not be redeemed again.
        // Pass through the ID token so that it can be validated and used as the identity that has signed in.
        // Do not pass through the access token as we are taking control over the token acquisition and don't want the middleware
        // to cache and reuse the access token itself.
        context.HandleCodeRedemption(string.Empty, result.IdToken);
    }

    public override Task TokenResponseReceived(TokenResponseReceivedContext context)
    {
        // Invoked after "authorization code" is redeemed for tokens at the token endpoint.
        base.TokenResponseReceived(context);
        // See if an account identifier was provided by a previous step.
        var accountId = context.Properties?.GetParameter<string>(AzureADIdentityProvider.ClaimTypeHomeAccountId);
        if (accountId != null && context.Principal != null)
        {
            // Add the account identifier claim so it can be used to look up the user's tokens later.
            var roundTripIdentity = context.Principal.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
            roundTripIdentity.AddClaim(new Claim(AzureADIdentityProvider.ClaimTypeHomeAccountId, accountId));
        }
        return Task.CompletedTask;
    }

    public override async Task RedirectToIdentityProviderForSignOut(RedirectContext context)
    {
        // Remove the user from the MSAL cache.
        await this.IdentityProvider.RemoveUserAsync(context.HttpContext);
        await base.RedirectToIdentityProviderForSignOut(context);
    }
}