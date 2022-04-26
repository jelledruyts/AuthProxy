namespace AuthProxy.Models;

// TODO-M: Can also put scopes and other config in proxy definition for a certain target/audience/profile (e.g. "AccountsDB" or "GraphAPI")?
public class TokenRequest
{
    public string? IdentityProvider { get; set; }
    public IList<string>? Scopes { get; set; }
    public string? ReturnUrl { get; set; } // If a redirect is required, determines where to redirect back after the interaction completed.
    public Actor Actor { get; set; }
}