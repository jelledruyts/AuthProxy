namespace AuthProxy.Models;

// Determines if a token is intended to impersonate a user (in which case we can request it interactively or via an OBO flow)
// or an app (in which case we can request it using a client credential (such as a client secret or certificate) or via
// an Azure managed identity.
public enum Actor
{
    User,
    App,
    AzureManagedIdentity
}