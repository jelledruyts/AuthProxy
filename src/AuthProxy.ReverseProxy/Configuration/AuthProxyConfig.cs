namespace AuthProxy.ReverseProxy.Configuration;

public class AuthProxyConfig
{
    public TokenIssuerConfig TokenIssuer { get; set; } = new TokenIssuerConfig();
    public BackendConfig Backend { get; set; } = new BackendConfig();
    public ApiConfig Api { get; set; } = new ApiConfig();
    public AuthenticationConfig Authentication { get; set; } = new AuthenticationConfig();
    public PoliciesConfig Policies { get; set; } = new PoliciesConfig();
}