namespace AuthProxy.Configuration;

public class IdentityProviderConfig
{
    public IdentityProviderType Type { get; set; } = IdentityProviderType.OpenIdConnect;
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Audience { get; set; }
    public string? CallbackPath { get; set; } = "/.auth/login/callback";
}