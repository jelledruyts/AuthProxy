namespace AuthProxy.Configuration;

public enum InboundPolicyAction
{
    None, // Not configured
    Allow, // Allow access
    Authenticate, // Require authentication
    Deny // Deny access
}