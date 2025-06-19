namespace AuthProxy.Models;

public class AuthenticationConfigMetadata
{
    public string? DefaultIdentityProvider { get; set; }
    public IList<IdentityProviderConfigMetadata> IdentityProviders { get; set; } = new List<IdentityProviderConfigMetadata>();
    public string? LogoutPath { get; set; }
    public string? LoginPath { get; set; }
    public IList<TokenRequestProfileConfigMetadata> TokenRequestProfiles { get; set; } = new List<TokenRequestProfileConfigMetadata>();
}