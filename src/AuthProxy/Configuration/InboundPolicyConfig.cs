namespace AuthProxy.Configuration;

public class InboundPolicyConfig
{
    public IList<string> PathPatterns { get; set; } = new List<string>();
    public InboundPolicyAction Action { get; set; }
    public IList<string> IdentityProviders { get; set; } = new List<string>();
}