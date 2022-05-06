namespace AuthProxy.Models;

public class ApiTokenRequest : TokenRequest
{
    public string? Profile { get; set; } // Either specify a configured token request profile, or all the properties below.
    public string? IdentityProvider { get; set; }
}