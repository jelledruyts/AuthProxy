namespace AuthProxy.Configuration;

public class TokenIssuerConfig
{
    public string Issuer { get; set; } = Defaults.TokenIssuerIssuer;
    public TimeSpan Expiration { get; set; } = Defaults.TokenIssuerExpiration;
    public IList<CertificateConfig> SigningCertificates { get; set; } = new List<CertificateConfig>();
}