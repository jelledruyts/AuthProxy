using System.Security.Claims;
using AuthProxy.Configuration;

namespace AuthProxy.Infrastructure;

// TODO: Add a claims transformation which can split a claim value into multiple claims, for example space-separated "scope" values.
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

        // TODO: Add information about the IdP that authenticated the user.
        // This and the "subject" transformation could be done with configurable expressions such as:
        //   "sub=claim:sub + '@' + claim:iss)"
        //   "auth-idp-name=idp:name"
        //   "auth-idp-type=idp:type"

        return Task.FromResult<IEnumerable<Claim>>(output);
    }
}