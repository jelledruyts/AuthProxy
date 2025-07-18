using AuthProxy.Models;

namespace AuthProxy.ReverseProxy.Configuration;

public class TokenRequestProfileConfig
{
    public string? Id { get; set; }
    public string? IdentityProvider { get; set; }
    public Actor Actor { get; set; }
    public IList<string> Scopes { get; set; } = new List<string>();
    public string? ReturnUrl { get; set; }
}