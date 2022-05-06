namespace AuthProxy.Configuration;

public class PoliciesConfig
{
    public IList<InboundPolicyConfig> Inbound { get; set; } = new List<InboundPolicyConfig>();
    public IList<OutboundPolicyConfig> Outbound { get; set; } = new List<OutboundPolicyConfig>();
}