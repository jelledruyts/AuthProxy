using AuthProxy.Configuration;
using Microsoft.Identity.Client;

namespace AuthProxy.IdentityProviders;

public class AzureADB2CIdentityProvider : AzureADIdentityProvider
{
    public AzureADB2CIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
    }

    protected override string GetTenantId(string authority)
    {
        // Take the first part of the path that is not equal to "tfp", as the following are all allowed authorities:
        //   https://contoso.b2clogin.com/tfp/contoso.com
        //   https://contoso.b2clogin.com/tfp/contoso.com/v2.0
        //   https://contoso.b2clogin.com/contoso.com
        //   https://contoso.b2clogin.com/contoso.com/v2.0
        //   https://idp.contoso.com/contoso.com
        var pathParts = new Uri(authority).AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (pathParts.Length == 1 || !string.Equals("tfp", pathParts[0], StringComparison.OrdinalIgnoreCase))
        {
            return pathParts[0];
        }
        return pathParts[1];
    }

    protected override IList<string> GetDefaultClaimTransformations()
    {
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        var claimTransformations = base.GetDefaultClaimTransformations();
        claimTransformations.Add(AuthProxyConstants.Defaults.NameClaimType);
        claimTransformations.Add("emails");
        claimTransformations.Add("tfp");
        return claimTransformations;
    }

    protected override ConfidentialClientApplicationBuilder GetConfidentialClientApplicationBuilder(HttpContext httpContext)
    {
        var builder = base.GetConfidentialClientApplicationBuilder(httpContext);
        builder = builder.WithB2CAuthority(this.Configuration.Authority); // Signal to MSAL that we're using B2C.
        return builder;
    }
}