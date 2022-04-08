namespace AuthProxy.Configuration;

public class InboundPolicyConfig
{
    public IList<string>? PathPatterns { get; set; }
    public PolicyAction Action { get; set; }
    public IList<string>? IdentityProviders { get; set; }
}