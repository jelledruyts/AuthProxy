namespace AuthProxy.Models;

public class TokenRequest
{
    public string? Profile { get; set; }
    public string? IdentityProvider { get; set; }
    public Actor? Actor { get; set; }
    public IList<string>? Scopes { get; set; }
    public string? ReturnUrl { get; set; } // If a redirect is required, determines where to redirect back after the interaction completed.
}