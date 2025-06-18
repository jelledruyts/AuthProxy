using System.Security.Claims;
using System.Text;
using AuthProxy.IdentityProviders;

namespace AuthProxy.Infrastructure;

public class ClaimsTransformer
{
    public IdentityProvider IdentityProvider { get; }
    public IList<string> ClaimTransformations { get; set; }

    public ClaimsTransformer(IdentityProvider identityProvider, IList<string> claimTransformations)
    {
        this.IdentityProvider = identityProvider;
        this.ClaimTransformations = claimTransformations;
    }

    public Task<ClaimsPrincipal?> TransformPrincipalAsync(ClaimsPrincipal? principal)
    {
        return TransformIdentitiesAsync(principal?.Identities ?? Enumerable.Empty<ClaimsIdentity>());
    }

    public async Task<ClaimsPrincipal?> TransformIdentitiesAsync(IEnumerable<ClaimsIdentity> identities)
    {
        ArgumentNullException.ThrowIfNull(this.IdentityProvider.Configuration.Id);
        var newIdentities = new List<ClaimsIdentity>();
        var metadataIdentity = default(ClaimsIdentity);
        var claimsToTransform = new List<Claim>();
        foreach (var identity in identities)
        {
            // Process each identity in the principal, except for the ones that are
            // constructed by the claims transformer itself (if called multiple times).
            if (identity.AuthenticationType == Constants.AuthenticationTypes.Metadata)
            {
                // Keep the existing metadata identity if it was already created by the claims transformer.
                metadataIdentity = identity;
            }
            else if (identity.AuthenticationType == Constants.AuthenticationTypes.BackendApp)
            {
                // Skip the identity that was already transformed by the claims transformer in a
                // previous pass, as a new one will be created based on the current set of claims.
            }
            else
            {
                // Add the original identity for future reference (internal to the proxy only).
                newIdentities.Add(identity);

                // Collect all claims from the identity to transform into a new identity for the backend app later on.
                foreach (var claim in identity.Claims)
                {
                    // If the claim type is not already present in the transformed claims, add it to the list.
                    // This avoids duplicating claims that are already transformed.
                    if (!claimsToTransform.Any(c => c.Type.Equals(claim.Type, StringComparison.OrdinalIgnoreCase)))
                    {
                        claimsToTransform.Add(claim);
                    }
                }
            }
        }

        // Transform the incoming claims into an identity that will be sent to the backend app.
        var transformedClaims = await TransformClaimsAsync(claimsToTransform);
        var backendAppIdentity = new ClaimsIdentity(transformedClaims, Constants.AuthenticationTypes.BackendApp);
        newIdentities.Add(backendAppIdentity);

        if (metadataIdentity == null)
        {
            // If no metadata identity was created yet, create a new local identity with additional
            // metadata about the authentication for future reference (internal to the proxy only).
            metadataIdentity = new ClaimsIdentity(new[]{
                new Claim(Constants.ClaimTypes.Metadata.IdentityProviderId, this.IdentityProvider.Configuration.Id),
                new Claim(Constants.ClaimTypes.Metadata.IdentityProviderType, this.IdentityProvider.Configuration.Type.ToString())
            }, Constants.AuthenticationTypes.Metadata);
        }
        newIdentities.Add(metadataIdentity);

        // Create a new claims principal containing the original identities, an identity holding
        // the transformed claims for the backend app, and a local identity with additional
        // metadata about the authentication.
        return new ClaimsPrincipal(newIdentities);
    }

    private Task<IEnumerable<Claim>> TransformClaimsAsync(IEnumerable<Claim> claims)
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

    private static IEnumerable<string> TransformExpression(string expression, IEnumerable<Claim> claims)
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