namespace AuthProxy.Configuration;

public class TokenIssuerConfig
{
    public string? Audience { get; set; }
    public string? Issuer { get; set; }
    public TimeSpan? Expiration { get; set; } = Defaults.TokenIssuerExpiration;
    public string? SigningSecret { get; set; }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(this.Audience);
        ArgumentNullException.ThrowIfNull(this.Issuer);
        ArgumentNullException.ThrowIfNull(this.Expiration);
        ArgumentNullException.ThrowIfNull(this.SigningSecret);
    }
}