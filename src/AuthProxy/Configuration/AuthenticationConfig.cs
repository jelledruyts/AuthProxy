namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig Cookie { get; set; } = new CookieConfig();
    public TokenIssuerConfig TokenIssuer { get; set; } = new TokenIssuerConfig();
    public string? DefaultIdentityProvider { get; set; }
    public IList<IdentityProviderConfig> IdentityProviders { get; set; } = new List<IdentityProviderConfig>();
    public IList<TokenRequestProfileConfig> TokenRequestProfiles { get; set; } = new List<TokenRequestProfileConfig>();
    // TODO-L: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc
}