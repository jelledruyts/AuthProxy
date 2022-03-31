namespace AuthProxy.Configuration;

public enum IdentityProviderType
{
    // Can be generic (OIDC, OAuth2, SAML2, ...) or specific (AzureAD, Auth0, ...)
    OpenIdConnect,
    AzureAD
}