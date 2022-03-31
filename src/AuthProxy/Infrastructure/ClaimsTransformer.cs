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
    public IdentityProviderConfig IdentityProvider { get; }
    public IDictionary<string, string> ClaimTransformations { get; set; }
    private readonly string outputSubjectClaimType;
    private readonly IEnumerable<string> inputSubjectClaimTypes;
    public string SubjectClaimValueSeparator { get; set; } = Defaults.SubjectClaimValueSeparator;

    public ClaimsTransformer(IdentityProviderConfig identityProvider, IDictionary<string, string> claimTransformations, string outputSubjectClaimType, IEnumerable<string> inputSubjectClaimTypes)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimTransformations = claimTransformations;
        this.outputSubjectClaimType = outputSubjectClaimType;
        this.inputSubjectClaimTypes = inputSubjectClaimTypes;
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
        foreach (var claim in claims.Where(c => !string.IsNullOrWhiteSpace(c.Type) && this.ClaimTransformations.ContainsKey(c.Type)))
        {
            var mappedClaimType = this.ClaimTransformations[claim.Type];
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