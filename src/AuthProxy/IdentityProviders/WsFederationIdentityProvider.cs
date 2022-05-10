using AuthProxy.Configuration;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.WsFederation;

namespace AuthProxy.IdentityProviders;

public class WsFederationIdentityProvider : IdentityProvider
{
    public WsFederationIdentityProvider(IdentityProviderConfig config, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(config, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
    }

    public override void AddAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        authenticationBuilder.AddWsFederation(this.AuthenticationScheme, options =>
        {
            // Set main options.
            options.MetadataAddress = this.Configuration.Authority; // The configuration's Authority should refer to the WS-Federation metadata document.
            options.Wtrealm = this.Configuration.ClientId; // The configuration's ClientId should refer to the "wtrealm" of the WS-Federation app.

            // Set token validation parameters.
            options.TokenValidationParameters.ValidAudiences = this.Configuration.AllowedAudiences; // TODO: Warn if there are no valid audiences configured.

            // Handle events.
            options.Events = GetEvents();
        });
    }

    protected virtual WsFederationEvents GetEvents()
    {
        var claimsTransformer = GetClaimsTransformer();
        return new WsFederationIdentityProviderEvents<WsFederationIdentityProvider>(this, claimsTransformer);
    }

    protected override IList<string> GetDefaultClaimTransformations()
    {
        var claimTransformations = base.GetDefaultClaimTransformations();
        // The mappings below are Microsoft-specific, as there isn't a standard with "expected" claims.
        // When using different IdPs, configuration allows to map other claim types.
        claimTransformations.Add("sub=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier + '@' + http://schemas.microsoft.com/identity/claims/identityprovider"); // Don't map the subject directly as it's unique within the IdP only, concatenate it with the issuer claim to avoid conflicts between different users with the same subject across IdPs.
        claimTransformations.Add("name=http://schemas.microsoft.com/identity/claims/displayname"); // Map the display name.
        claimTransformations.Add("email=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"); // Map the email.
        claimTransformations.Add("roles=http://schemas.microsoft.com/ws/2008/06/identity/claims/role"); // Map the roles.
        claimTransformations.Add("amr=http://schemas.microsoft.com/claims/authnmethodsreferences"); // Map the Authentication Methods References.
        return claimTransformations;
    }

    public override Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request)
    {
        throw new NotImplementedException("WS-Federation is only used for user authentication, not for token authorization.");
    }
}