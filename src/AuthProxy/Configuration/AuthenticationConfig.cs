namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig Cookie { get; set; } = new CookieConfig();
    public TokenIssuerConfig TokenIssuer { get; set; } = new TokenIssuerConfig();
    public string? DefaultIdentityProvider { get; set; }
    public IList<IdentityProviderConfig> IdentityProviders { get; set; } = new List<IdentityProviderConfig>();
    public string LogoutPath { get; set; } = Defaults.LogoutPath;
    public string LoginPath { get; set; } = Defaults.LoginPath;
    public string LoginCallbackPath { get; set; } = Defaults.LoginCallbackPath;
    public string PostLogoutReturnUrlQueryParameterName { get; set; } = Defaults.PostLogoutReturnUrlQueryParameterName;
    public string PostLoginReturnUrlQueryParameterName { get; set; } = Defaults.PostLoginReturnUrlQueryParameterName;    
    public IList<TokenRequestProfileConfig> TokenRequestProfiles { get; set; } = new List<TokenRequestProfileConfig>();
    // TODO: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc
}