namespace AuthProxy.Configuration;

public class OutboundPolicyConfig
{
    public IList<string> UrlPatterns { get; set; } = new List<string>();
    public OutboundPolicyAction Action { get; set; }
    public string? TokenRequestProfile { get; set; }
}