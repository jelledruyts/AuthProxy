using AuthProxy.Models;

namespace AuthProxy.Configuration;

public class TokenRequestProfileConfig
{
    public string? Name { get; set; }
    public string? IdentityProvider { get; set; }
    public Actor Actor { get; set; }
    public IList<string> Scopes { get; set; } = new List<string>();
    public string? ReturnUrl { get; set; }
}