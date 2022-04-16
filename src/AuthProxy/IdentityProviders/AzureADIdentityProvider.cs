using AuthProxy.Configuration;
using AuthProxy.Infrastructure;

namespace AuthProxy.IdentityProviders;

// TODO: The "login_hint" claim (if present) of the current principal's "original" (federated) identity
// can be used as the "logout_hint" when a logout is requested towards the IdP.
// See https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request.

public class AzureADIdentityProvider : OpenIdConnectIdentityProvider
{
    public AzureADIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
        ArgumentNullException.ThrowIfNull(configuration.Authority);
        // Ensure that the configured Azure AD authority is using v2.0.
        if (!configuration.Authority.Contains("/v2.0", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException($"The Azure AD identity provider \"{configuration.Name}\" with Authority URL \"{configuration.Authority}\" doesn't use the required v2.0 endpoint (for example, \"https://login.microsoftonline.com/contoso.com/v2.0\").");
        }
    }

    protected override ClaimsTransformer GetClaimsTransformer()
    {
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        var transformer = base.GetClaimsTransformer();
        transformer.ClaimTransformations.Add("name=preferred_username");
        transformer.ClaimTransformations.Add("roles");
        transformer.ClaimTransformations.Add("email");
        return transformer;
    }
}