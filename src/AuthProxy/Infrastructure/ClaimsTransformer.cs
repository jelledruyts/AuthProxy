using System.Security.Claims;
using System.Text;
using AuthProxy.Configuration;

namespace AuthProxy.Infrastructure;

public class ClaimsTransformer
{
    public IdentityProviderConfig IdentityProvider { get; }
    public IList<string> ClaimTransformations { get; set; }

    public ClaimsTransformer(IdentityProviderConfig identityProvider, IList<string> claimTransformations)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimTransformations = claimTransformations;
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

        var parsedClaimTransformations = this.ClaimTransformations.ParseKeyValuePairs(true);

        foreach (var claimTransformation in parsedClaimTransformations)
        {
            if (!string.IsNullOrWhiteSpace(claimTransformation.Value))
            {
                foreach (var claimValue in TransformExpression(claimTransformation.Value, claims))
                {
                    if (!string.IsNullOrWhiteSpace(claimValue))
                    {
                        output.Add(new Claim(claimTransformation.Key, claimValue));
                    }
                }
            }
        }

        return Task.FromResult<IEnumerable<Claim>>(output);
    }

    public static IEnumerable<string> TransformExpression(string expression, IEnumerable<Claim> claims)
    {
        var transformedClaimValues = new List<StringBuilder>();
        // Support a simple concatenation expression with + signs and either a claim name or a static string (in single quotes).
        // For example: "'---' + claim1 + claim2 + '.' + claim3 + '---'".
        transformedClaimValues.Add(new StringBuilder());
        foreach (var part in expression.Split('+', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith('\''))
            {
                if (!part.EndsWith('\''))
                {
                    throw new ArgumentException($"Expression is not well-formed: \"{expression}\".");
                }
                // A constant string - append it to the output of all transformed claim values.
                foreach (var transformedClaimValue in transformedClaimValues)
                {
                    transformedClaimValue.Append(part.Substring(1, part.Length - 2));
                }
            }
            else
            {
                // A claim name - append the claim value(s).
                var claimValues = claims.Where(c => c.Type == part && !string.IsNullOrWhiteSpace(c.Value)).Select(c => c.Value).ToArray();
                if (claimValues.Any())
                {
                    if (claimValues.Length > 1)
                    {
                        // If there are multiple values for this claim type, add additional transformed claim values to the output.
                        var existingTransformedClaimValues = transformedClaimValues.Select(t => t.ToString()).ToArray();
                        for (var i = 0; i < claimValues.Length - 1; i++)
                        {
                            foreach (var existingTransformedClaimValue in existingTransformedClaimValues)
                            {
                                transformedClaimValues.Add(new StringBuilder(existingTransformedClaimValue));
                            }
                        }
                    }
                    for (var i = 0; i < transformedClaimValues.Count; i++)
                    {
                        transformedClaimValues[i].Append(claimValues[i / (transformedClaimValues.Count / claimValues.Length)]);
                    }
                }
            }
        }
        return transformedClaimValues.Select(s => s.ToString());
    }
}