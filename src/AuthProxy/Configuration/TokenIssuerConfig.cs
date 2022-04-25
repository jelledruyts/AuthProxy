namespace AuthProxy.Configuration;

public class TokenIssuerConfig
{
    public string Audience { get; set; } = Defaults.TokenIssuerAudience;
    public string Issuer { get; set; } = Defaults.TokenIssuerIssuer;
    public TimeSpan Expiration { get; set; } = Defaults.TokenIssuerExpiration;
    public string? SigningSecret { get; set; }
}