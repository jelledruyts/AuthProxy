namespace AuthProxy.Configuration;

public class AuthProxyConfig
{
    public const string ConfigSectionName = "AuthProxy";

    public BackendConfig? Backend { get; set; }
    public AuthenticationConfig? Authentication { get; set; }
}