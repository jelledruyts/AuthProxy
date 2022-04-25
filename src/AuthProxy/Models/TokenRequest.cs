namespace AuthProxy.Models;

// TODO-L: Can also put scopes and other config in proxy definition for a certain target/audience/profile (e.g. "AccountsDB" or "GraphAPI")?
public class TokenRequest
{
    public string? IdentityProvider { get; set; } // TODO-M: If empty: use default IdP
    public IList<string>? Scopes { get; set; }
    public string? ReturnUrl { get; set; } // If a redirect is required, determines where to redirect back after the interaction completed.
    public string? Actor { get; set; } // Enum to state if it's for a user (in which case direct or OBO) or for the app (in which case using client secret/cert/MSI/...)?
}