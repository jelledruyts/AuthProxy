using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProviderJwtBearerEvents<TIdentityProvider> : JwtBearerEvents where TIdentityProvider : IdentityProvider
{
    public TIdentityProvider IdentityProvider { get; }
    public ClaimsTransformer ClaimsTransformer { get; }

    public OpenIdConnectIdentityProviderJwtBearerEvents(TIdentityProvider identityProvider, ClaimsTransformer claimsTransformer)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimsTransformer = claimsTransformer;
    }

    public async override Task TokenValidated(TokenValidatedContext context)
    {
        // Invoked when the bearer token has been validated and produced an AuthenticationTicket.
        context.Principal = await this.ClaimsTransformer.TransformPrincipalAsync(context.Principal);

        // See if a JWT bearer token was validated.
        var bearerToken = context.SecurityToken as JwtSecurityToken;
        if (bearerToken != null && context.Principal != null)
        {
            // Add the token as a claim to the metadata identity so it can be used to look up the original
            // token later, for example to perform an On-Behalf-Of flow.
            var metadataIdentity = context.Principal.GetOrCreateIdentity(Constants.AuthenticationTypes.Metadata);
            metadataIdentity.AddClaim(new Claim(OpenIdConnectIdentityProvider.ClaimTypeBearerToken, bearerToken.RawData));
        }
    }
}