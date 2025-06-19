namespace AuthProxy.ReverseProxy.Configuration;

public class OutboundPolicyConfig
{
    public string? UrlPattern { get; set; }
    public OutboundPolicyAction Action { get; set; }
    public string? TokenRequestProfile { get; set; }
}