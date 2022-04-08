using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure.IdentityProviders;

public class OpenIdConnectHandler
{
    private static readonly string[] defaultClaimTransformations = {
        // "iss = ", // Don't map the issuer, the backend app can be reached through multiple IdPs and it shouldn't care which one was used.
        // "azp = ", // Don't map the authorized party, the backend app can be reached through multiple clients and it shouldn't care which one was used.
        // "aud = " , // Don't map the audience, the backend app can be reached through multiple IdPs/audiences and it shouldn't care which one was used.
        "sub = sub + '@' + iss", // Don't map the subject directly as it's unique within the IdP only, concatenate it with the issuer claim to avoid conflicts between different users with the same subject across IdPs.
        "acr", // Map the Authentication Context Class Reference to itself (shorthand syntax).
        "amr" // Map the Authentication Methods References to itself (shorthand syntax).
    };

    public OpenIdConnectHandler(IdentityProviderConfig identityProvider, OpenIdConnectOptions options, string loginCallbackPath)
    {
        // Set main options.
        options.ClaimActions.Clear(); // Don't change any incoming claims, let the claims transformer do that.
        options.Authority = identityProvider.Authority;
        if (identityProvider.Scopes != null)
        {
            foreach (var scope in identityProvider.Scopes)
            {
                options.Scope.Add(scope);
            }
        }
        // options.Scope.Add(OpenIdConnectScope.OfflineAccess); // TODO: Only if needed, request a refresh token as part of the authorization code flow.
        options.ClientId = identityProvider.ClientId;
        options.ClientSecret = identityProvider.ClientSecret;
        options.CallbackPath = loginCallbackPath; // Note that the callback path must be unique per identity provider.

        // Set token validation parameters.
        options.TokenValidationParameters.ValidAudiences = identityProvider.AllowedAudiences;
        // TODO: Warn if there are no valid audiences configured.

        // Handle events.
        var claimsTransformer = GetClaimsTransformer(identityProvider);
        options.Events = GetEvents(identityProvider, claimsTransformer);
    }

    protected virtual ClaimsTransformer GetClaimsTransformer(IdentityProviderConfig identityProvider)
    {
        var claimTransformations = defaultClaimTransformations.Concat(identityProvider.ClaimTransformations ?? Array.Empty<string>()).ToList();
        return new ClaimsTransformer(identityProvider, claimTransformations);
    }

    protected virtual OpenIdConnectEvents GetEvents(IdentityProviderConfig identityProvider, ClaimsTransformer claimsTransformer)
    {
        return new OpenIdConnectHandlerEvents(identityProvider, claimsTransformer);
    }
}