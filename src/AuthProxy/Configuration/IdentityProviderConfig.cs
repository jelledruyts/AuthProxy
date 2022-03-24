namespace AuthProxy.Configuration;

public class IdentityProviderConfig
{
    public string? Name { get; set; }
    public IdentityProviderType Type { get; set; } = IdentityProviderType.OpenIdConnect;
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; } // TODO: ClientSecretEnvVarName/Reference/...?
    public string[]? Scopes { get; set; }
    public string[]? AllowedAudiences { get; set; }
    public string[]? ClaimTransformations { get; set; }
    public string[]? AdditionalParameters { get; set; }
    public string[]? AdditionalParametersForLogout { get; set; }
    public string? LoginPath { get; set; }
    public string? LoginCallbackPath { get; set; }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(this.Name);
        // TODO: Check that Name is acceptable in URL and does not conflict with default authentication scheme (Defaults.AuthenticationScheme).
        // TODO: Warn if there are no valid audiences configured.
        // TODO: Complete validation.
    }
}