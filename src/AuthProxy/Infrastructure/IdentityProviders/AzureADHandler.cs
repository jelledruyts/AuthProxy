using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure.IdentityProviders;

// TODO: The "login_hint" claim (if present) of the current principal's "original" (federated) identity
// can be used as the "logout_hint" when a logout is requested towards the IdP.
// See https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request.

public class AzureADHandler : OpenIdConnectHandler
{
    public AzureADHandler(IdentityProviderConfig identityProvider, OpenIdConnectOptions options, string loginCallbackPath)
        : base(identityProvider, options, loginCallbackPath)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Authority);
        // Ensure that the configured Azure AD authority is using v2.0.
        if (!identityProvider.Authority.Contains("/v2.0", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException($"The Azure AD identity provider \"{identityProvider.Name}\" with Authority URL \"{identityProvider.Authority}\" doesn't use the required v2.0 endpoint (for example, \"https://login.microsoftonline.com/contoso.com/v2.0\").");
        }
    }

    protected override ClaimsTransformer GetClaimsTransformer(IdentityProviderConfig identityProvider)
    {
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        var transformer = base.GetClaimsTransformer(identityProvider);
        transformer.ClaimTransformations.Add("name=preferred_username");
        transformer.ClaimTransformations.Add("roles");
        transformer.ClaimTransformations.Add("email");
        return transformer;
    }
}