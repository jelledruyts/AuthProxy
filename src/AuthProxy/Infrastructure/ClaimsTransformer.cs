using System.Security.Claims;
using AuthProxy.Configuration;

namespace AuthProxy.Infrastructure;

// TODO: Change claims transformations with expression syntax
//   Inputs: claims (claim[roles]), configuration/metadata (config[idp.name]), constant strings (string['foo'])
//   Functions: +, split, join
// Examples:
// - "roles=claim[http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname]" => returns all "surname" claim values with their original claim type
// - "roles=claim[roles]" => returns all "roles" claim values with their original claim type
//     Example: ( "roles": "read", "roles": "write" ) => ( "roles": "read", "roles": "write" )
// - "roles=roles" => returns all "roles" claim values with their original claim type (shorter syntax to simplify "claim[<name>]")
// - "roles" => returns all "roles" claim values with their original claim type (short hand syntax)
// - "ver=string['1.0']" => returns a "ver" claim value with a constant string
// - "ver='1.0'" => returns a "ver" claim value with a constant string (shorter syntax where quotes imply string[])
// - "scp=split(scp, ' ')" => returns all "scp" claim values and for each value splits the string into multiple values
//     Example: ( "scp": "a b c", "scp": "a d" ) => ( "scp: "a", "scp: "b", "scp: "c", "scp: "a", "scp: "d" )
// - "roles=join(roles, ' ')" => returns one "roles" claim value with the concatenated values of all original "roles" claim values
//     Example: ( "roles": "read", "roles": "write" ) => ( "roles": "read write" )
// - "idp-name=idp[name]" => returns a claim with a configuration value of the identity provider which authenticated the user
// - "sub=sub + '@' + iss" => returns claims with a concatenation of the "sub" and "iss" claim values (cartesian product of all input claim values)
//     Example: ( "sub": "a", "sub": "b", "iss": "x", "iss": "y" ) => ( "sub": "a@x", "sub": "a@y", "sub": "b@x", "sub": "b@y" )
// - "sub=join(sub, ' ') + '@' + join(iss, ' ')" => returns a single claims with a concatenation of the joined "sub" and "iss" claim values
//     Example: ( "sub": "a", "sub": "b", "iss": "x", "iss": "y" ) => ( "sub": "a b@x y" )
public class ClaimsTransformer
{
    private readonly IdentityProviderConfig identityProvider;
    private readonly string outputSubjectClaimType;
    private readonly IEnumerable<string> inputSubjectClaimTypes;
    private readonly IDictionary<string, string> claimTransformations;
    public string SubjectClaimValueSeparator { get; set; } = Defaults.SubjectClaimValueSeparator;

    public ClaimsTransformer(IdentityProviderConfig identityProvider)
    {
        this.identityProvider = identityProvider;
        var configuredClaimTransformations = identityProvider.ClaimTransformations.ParseKeyValuePairs(true);
        if (identityProvider.Type == IdentityProviderType.OpenIdConnect)
        {
            // TODO: (Re)use constants for claim types.
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
            this.outputSubjectClaimType = "sub"; // TODO: Make configurable?
            this.inputSubjectClaimTypes = new[] { "sub", "iss" }; // TODO: Make configurable?
            this.claimTransformations = defaultClaimTransformations;
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(identityProvider.Type), $"Unknown {nameof(IdentityProviderType)}: \"{identityProvider.Type.ToString()}\".");
        }
    }

    public async Task<ClaimsPrincipal?> TransformAsync(ClaimsPrincipal? principal)
    {
        // Transform the incoming claims and create a new claims principal.
        var identity = principal?.Identity as ClaimsIdentity;
        if (identity != null)
        {
            var transformedClaims = await TransformAsync(identity.Claims);
            var transformedIdentity = new ClaimsIdentity(transformedClaims, identity.AuthenticationType);
            principal = new ClaimsPrincipal(transformedIdentity);
        }
        return principal;
    }

    public Task<IEnumerable<Claim>> TransformAsync(IEnumerable<Claim> claims)
    {
        var output = new List<Claim>();

        // Return (only) the mapped claims.
        foreach (var claim in claims.Where(c => !string.IsNullOrWhiteSpace(c.Type) && this.claimTransformations.ContainsKey(c.Type)))
        {
            var mappedClaimType = this.claimTransformations[claim.Type];
            if (!string.IsNullOrWhiteSpace(mappedClaimType))
            {
                output.Add(new Claim(mappedClaimType, claim.Value, claim.ValueType));
            }
        }

        // Add a specific claim for the "subject".
        var inputSubjectClaims = this.inputSubjectClaimTypes.SelectMany(inputSubjectClaimType => claims.Where(c => c.Type == inputSubjectClaimType).Select(c => c.Value));
        output.Add(new Claim(this.outputSubjectClaimType, string.Join(this.SubjectClaimValueSeparator, inputSubjectClaims)));

        return Task.FromResult<IEnumerable<Claim>>(output);
    }
}