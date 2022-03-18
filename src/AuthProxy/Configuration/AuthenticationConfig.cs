namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig? Cookie { get; set; }
    public TokenIssuerConfig? TokenIssuer { get; set; }
    public IdentityProviderConfig? IdentityProvider { get; set; } // TODO: This should be a list of IdPs.
}