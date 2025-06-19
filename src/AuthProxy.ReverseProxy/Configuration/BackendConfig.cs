namespace AuthProxy.ReverseProxy.Configuration;

public class BackendConfig
{
    public string? Url { get; set; }
    public string Audience { get; set; } = AuthProxyConstants.Defaults.TokenAudience;
    public HostPolicy HostPolicy { get; set; }
    public string? HostName { get; set; }
}