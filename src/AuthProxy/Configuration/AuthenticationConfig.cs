namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig? Cookie { get; set; }
    public TokenIssuerConfig? TokenIssuer { get; set; }
    public IList<IdentityProviderConfig>? IdentityProviders { get; set; }
    // TODO: Add "DefaultIdentityProviderName" configuration property to be explicit?
    // TODO: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc
}