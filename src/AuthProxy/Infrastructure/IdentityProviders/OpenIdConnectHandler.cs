using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure.IdentityProviders;

public class OpenIdConnectHandler
{
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

        // Handle events.
        var claimsTransformer = GetClaimsTransformer(identityProvider);
        options.Events = GetEvents(identityProvider, claimsTransformer);
    }

    protected virtual ClaimsTransformer GetClaimsTransformer(IdentityProviderConfig identityProvider)
    {
        // TODO: (Re)use constants for claim types.
        var configuredClaimTransformations = identityProvider.ClaimTransformations.ParseKeyValuePairs(true);
        var defaultClaimTransformations = new Dictionary<string, string>()
        {
            // For defined claims in the  ID token, see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
            { "iss", "" }, // Don't map the issuer, the backend app can be reached through multiple IdPs and it shouldn't care which one was used.
            { "sub", "" }, // Don't map the subject as it's unique within the IdP only; the final subject claim will be concatenated with the issuer claim to avoid conflicts between different users with the same subject across IdPs.
            { "aud", "" }, // Don't map the audience, the backend app can be reached through multiple IdPs/audiences and it shouldn't care which one was used.
            { "acr", "acr" }, // Map the Authentication Context Class Reference.
            { "amr", "amr" }, // Map the Authentication Methods References.
            { "azp", "" } // Don't map the authorized party, the backend app can be reached through multiple clients and it shouldn't care which one was used.
        };
        defaultClaimTransformations.Merge(configuredClaimTransformations);
        var outputSubjectClaimType = "sub"; // TODO: Make configurable? Becomes obsolete with expression syntax.
        var inputSubjectClaimTypes = new[] { "sub", "iss" }; // TODO: Make configurable? Becomes obsolete with expression syntax.
        return new ClaimsTransformer(identityProvider, defaultClaimTransformations, outputSubjectClaimType, inputSubjectClaimTypes);
    }

    protected virtual OpenIdConnectEvents GetEvents(IdentityProviderConfig identityProvider, ClaimsTransformer claimsTransformer)
    {
        return new OpenIdConnectHandlerEvents(identityProvider, claimsTransformer);
    }
}