namespace AuthProxy.ReverseProxy.Configuration;

public class InboundPolicyConfig
{
    public IList<string> PathPatterns { get; set; } = new List<string>();
    public InboundPolicyAction Action { get; set; }
    public InboundPolicyConflictAction UnauthenticatedAction { get; set; }
    public InboundPolicyConflictAction AuthenticatedWithUnallowedIdentityProviderAction { get; set; }
    public IList<string> IdentityProviders { get; set; } = new List<string>();
}