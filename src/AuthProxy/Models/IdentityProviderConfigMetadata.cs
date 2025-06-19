namespace AuthProxy.Models;

public class IdentityProviderConfigMetadata
{
    public string? Id { get; set; }
    public IdentityProviderType? Type { get; set; }
    public string? DisplayName { get; set; }
    public string? LoginPath { get; set; }
}