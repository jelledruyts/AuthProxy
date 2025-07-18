using AuthProxy.Models;

namespace AuthProxy.ReverseProxy.Configuration;

public class IdentityProviderConfig
{
    public string? Id { get; set; }
    public IdentityProviderType Type { get; set; } = IdentityProviderType.OpenIdConnect;
    public string? DisplayName { get; set; }
    public string? Authority { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; } // TODO: ClientSecretEnvVarName/Reference/...?
    public string ResponseType { get; set; } = Constants.Defaults.ResponseType;
    public bool UsePkce { get; set; } = Constants.Defaults.UsePkce;
    public bool GetClaimsFromUserInfoEndpoint { get; set; } = Constants.Defaults.GetClaimsFromUserInfoEndpoint;
    public IList<string> DefaultScopes { get; set; } = new List<string>(); // Defines scopes that are always requested (typically standard OIDC scopes such as "email")
    public IList<string> SignInScopes { get; set; } = new List<string>(); // Defines scopes that are requested when the user is requested to sign in
    public IList<string> TokenRequestScopes { get; set; } = Constants.Defaults.TokenRequestScopes; // Defines scopes that are requested as part of a token request
    public IList<string> AllowedAudiences { get; set; } = new List<string>();
    public IList<string> AllowedIssuers { get; set; } = new List<string>();
    public IList<string> ClaimTransformations { get; set; } = new List<string>();
    public IList<string> AdditionalParameters { get; set; } = new List<string>();
    public IList<string> AdditionalParametersForLogout { get; set; } = new List<string>();
    public string? LoginPath { get; set; }
    public string? LoginCallbackPath { get; set; }
}