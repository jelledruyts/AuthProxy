namespace AuthProxy.Configuration;

public class TokenIssuerConfig
{
    public string? Audience { get; set; }
    public string? Issuer { get; set; }
    public TimeSpan? Expiration { get; set; }
    public string? SigningSecret { get; set; }
}