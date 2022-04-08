namespace AuthProxy.Configuration;

public class AuthProxyConfig
{
    public BackendConfig? Backend { get; set; }
    public PoliciesConfig? Policies { get; set; }
    public AuthenticationConfig? Authentication { get; set; }
}