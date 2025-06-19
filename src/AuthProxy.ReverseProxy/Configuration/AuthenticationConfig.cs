namespace AuthProxy.ReverseProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig Cookie { get; set; } = new CookieConfig();
    public string? DefaultIdentityProvider { get; set; }
    public IList<IdentityProviderConfig> IdentityProviders { get; set; } = new List<IdentityProviderConfig>();
    public string LogoutPath { get; set; } = Constants.Defaults.LogoutPath;
    public string LoginPath { get; set; } = Constants.Defaults.LoginPath;
    public string LoginCallbackPath { get; set; } = Constants.Defaults.LoginCallbackPath;
    public string PostLogoutReturnUrlQueryParameterName { get; set; } = Constants.Defaults.PostLogoutReturnUrlQueryParameterName;
    public string PostLoginReturnUrlQueryParameterName { get; set; } = Constants.Defaults.PostLoginReturnUrlQueryParameterName;
    public IList<TokenRequestProfileConfig> TokenRequestProfiles { get; set; } = new List<TokenRequestProfileConfig>();
    // TODO: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc
}