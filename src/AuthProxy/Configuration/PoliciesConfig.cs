namespace AuthProxy.Configuration;

public class PoliciesConfig
{
    public IList<InboundPolicyConfig>? Inbound { get; set; }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(this.Inbound);
        foreach (var inboundPolicy in this.Inbound)
        {
            inboundPolicy.Validate();
        }
    }
}