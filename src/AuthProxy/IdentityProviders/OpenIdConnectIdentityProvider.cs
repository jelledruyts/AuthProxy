using AuthProxy.Configuration;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProvider : IdentityProvider
{
    private static readonly string[] defaultClaimTransformations = {
        // "iss = ", // Don't map the issuer, the backend app can be reached through multiple IdPs and it shouldn't care which one was used.
        // "azp = ", // Don't map the authorized party, the backend app can be reached through multiple clients and it shouldn't care which one was used.
        // "aud = " , // Don't map the audience, the backend app can be reached through multiple IdPs/audiences and it shouldn't care which one was used.
        "sub = sub + '@' + iss", // Don't map the subject directly as it's unique within the IdP only, concatenate it with the issuer claim to avoid conflicts between different users with the same subject across IdPs.
        "acr", // Map the Authentication Context Class Reference to itself (shorthand syntax).
        "amr" // Map the Authentication Methods References to itself (shorthand syntax).
    };

    public OpenIdConnectIdentityProvider(IdentityProviderConfig config, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(config, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
    }

    public override void AddAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        authenticationBuilder.AddOpenIdConnect(this.AuthenticationScheme, options =>
        {
            // Set main options.
            options.ClaimActions.Clear(); // Don't change any incoming claims, let the claims transformer do that.
            options.Authority = this.Configuration.Authority;
            if (this.Configuration.Scopes != null)
            {
                foreach (var scope in this.Configuration.Scopes)
                {
                    options.Scope.Add(scope);
                }
            }
            // options.Scope.Add(OpenIdConnectScope.OfflineAccess); // TODO: Only if needed, request a refresh token as part of the authorization code flow.
            options.ClientId = this.Configuration.ClientId;
            options.ClientSecret = this.Configuration.ClientSecret;
            options.CallbackPath = this.LoginCallbackPath; // Note that the callback path must be unique per identity provider.

            // Set token validation parameters.
            options.TokenValidationParameters.ValidAudiences = this.Configuration.AllowedAudiences;
            // TODO: Warn if there are no valid audiences configured.

            // Handle events.
            var claimsTransformer = GetClaimsTransformer();
            options.Events = GetEvents(claimsTransformer);
        });
    }

    protected virtual ClaimsTransformer GetClaimsTransformer()
    {
        var claimTransformations = defaultClaimTransformations.Concat(this.Configuration.ClaimTransformations ?? Array.Empty<string>()).ToList();
        return new ClaimsTransformer(this, claimTransformations);
    }

    protected virtual OpenIdConnectEvents GetEvents(ClaimsTransformer claimsTransformer)
    {
        return new OpenIdConnectIdentityProviderEvents(this, claimsTransformer);
    }
}