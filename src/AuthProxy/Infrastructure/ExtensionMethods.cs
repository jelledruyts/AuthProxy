using System.Security.Claims;

namespace AuthProxy.Infrastructure;

public static class ExtensionMethods
{
    public static IDictionary<string, string> ParseKeyValuePairs(this IEnumerable<string?>? keyValuePairs, bool allowShorthandForm)
    {
        var result = new Dictionary<string, string>();
        if (keyValuePairs != null)
        {
            foreach (var keyValue in keyValuePairs)
            {
                if (keyValue != null)
                {
                    var parts = keyValue.Split('=', StringSplitOptions.TrimEntries);
                    var key = parts[0];
                    if (parts.Length == 1 && allowShorthandForm)
                    {
                        // The value "<key>" is short hand syntax for "<key>=<key>".
                        result[key] = key;
                    }
                    else if (parts.Length != 2)
                    {
                        throw new ArgumentException($"Could not parse key/value pair: \"keyValue\".", nameof(keyValuePairs));
                    }
                    else
                    {
                        result[key] = parts[1];
                    }
                }
            }
        }
        return result;
    }

    public static void Merge(this IDictionary<string, string> target, IDictionary<string, string> source)
    {
        source.ToList().ForEach(x => target[x.Key] = x.Value);
    }

    public static ClaimsIdentity? GetIdentity(this ClaimsPrincipal principal, string authenticationType)
    {
        return principal.Identities.SingleOrDefault(i => i.AuthenticationType == authenticationType);
    }

    public static ClaimsIdentity GetOrCreateIdentity(this ClaimsPrincipal principal, string authenticationType)
    {
        var identity = principal.GetIdentity(authenticationType);
        if (identity == null)
        {
            identity = new ClaimsIdentity(Array.Empty<Claim>(), authenticationType);
            principal.AddIdentity(identity);
        }
        return identity;
    }
}