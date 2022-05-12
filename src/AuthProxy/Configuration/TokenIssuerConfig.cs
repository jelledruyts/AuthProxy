namespace AuthProxy.Configuration;

public class TokenIssuerConfig
{
    public string Issuer { get; set; } = AuthProxyConstants.Defaults.TokenIssuer;
    public TimeSpan Expiration { get; set; } = Constants.Defaults.TokenIssuerExpiration;
    public IList<CertificateConfig> SigningCertificates { get; set; } = new List<CertificateConfig>();
}