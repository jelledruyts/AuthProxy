namespace AuthProxy.Configuration;

public enum PolicyAction
{
    None, // Not configured
    Allow, // Allow access
    Authenticate, // Require authentication
    Deny // Deny access
}