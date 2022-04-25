namespace AuthProxy.Configuration;

public class IdentityProviderConfig
{
    public string? Name { get; set; }
    public IdentityProviderType Type { get; set; } = IdentityProviderType.OpenIdConnect;
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; } // TODO-L: ClientSecretEnvVarName/Reference/...?
    public bool AllowRefreshTokens { get; set; } = Defaults.AllowRefreshTokens;
    public IList<string> Scopes { get; set; } = new List<string>();
    public IList<string> AllowedAudiences { get; set; } = new List<string>();
    public IList<string> ClaimTransformations { get; set; } = new List<string>();
    public IList<string> AdditionalParameters { get; set; } = new List<string>();
    public IList<string> AdditionalParametersForLogout { get; set; } = new List<string>();
    public string? LoginPath { get; set; }
    public string? LoginCallbackPath { get; set; }
}