using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.Infrastructure.IdentityProviders;

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
        var transformer = base.GetClaimsTransformer(identityProvider);
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        transformer.ClaimTransformations.Add("preferred_username", "name");
        transformer.ClaimTransformations.Add("roles", "roles");
        transformer.ClaimTransformations.Add("email", "email");
        return transformer;
    }
}