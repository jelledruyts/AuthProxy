namespace AuthProxy.Configuration;

public enum InboundPolicyConflictAction
{
    None, // Not configured
    Challenge, // Prompt for authentication (for example, redirect to login page)
    Deny // Deny access
}