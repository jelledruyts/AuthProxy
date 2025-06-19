using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthProxy.ReverseProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthProxy.ReverseProxy.IdentityProviders;

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
        if (context.Principal != null)
        {
            // Add the token as a claim to the roundtrip identity so it can be used to look up the original
            // token later, for example to perform an On-Behalf-Of flow.
            var rawToken = default(string?);
            if (context.SecurityToken is JwtSecurityToken jwtSecurityToken)
            {
                rawToken = jwtSecurityToken.RawData;
            }
            if (context.SecurityToken is JsonWebToken jsonWebToken)
            {
                rawToken = jsonWebToken.EncodedToken;
            }
            if (rawToken != null)
            {
                var roundTripIdentity = context.Principal.GetOrCreateIdentity(Constants.AuthenticationTypes.RoundTrip);
                roundTripIdentity.AddClaim(new Claim(Constants.ClaimTypes.BearerToken, rawToken));
            }
        }
    }
}