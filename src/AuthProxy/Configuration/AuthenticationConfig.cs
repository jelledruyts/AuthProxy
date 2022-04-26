namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig Cookie { get; set; } = new CookieConfig();
    public TokenIssuerConfig TokenIssuer { get; set; } = new TokenIssuerConfig();
    public IList<IdentityProviderConfig> IdentityProviders { get; set; } = new List<IdentityProviderConfig>();
    public string? DefaultIdentityProvider { get; set; }
    // TODO-L: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc
}