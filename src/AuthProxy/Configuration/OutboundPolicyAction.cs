namespace AuthProxy.Configuration;

public enum OutboundPolicyAction
{
    None, // Not configured
    AttachBearerToken // Attach a bearer token to the outbound call
}