namespace AuthProxy.Models;

public class TokenRequest
{
    public Actor? Actor { get; set; }
    public IList<string>? Scopes { get; set; }
    public string? ReturnUrl { get; set; } // If a redirect is required, determines where to redirect back after the interaction completed.
}