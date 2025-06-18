namespace AuthProxy.Models;

// This file is shared with the AuthProxy.Client project, so that models can be
// maintained in one place, while still avoiding the projects to have a runtime
// dependency on each other.

public enum IdentityProviderType
{
    // Can be generic (OIDC, OAuth2, SAML2, ...) or specific (AzureAD, Auth0, ...)
    OpenIdConnect,
    WsFederation,
    AzureAD,
    AzureADB2C
}