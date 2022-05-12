namespace AuthProxy.Client;

public class AuthProxyOptions
{
    public string? BaseUrl { get; set; }
    public bool AutoRedirectWhenRequired { get; set; } = true;
    public string? ValidIssuer { get; set; } = AuthProxyConstants.Defaults.TokenIssuer;
    public string? ValidAudience { get; set; } = AuthProxyConstants.Defaults.TokenAudience;
    public string? NameClaimType { get; set; } = AuthProxyConstants.Defaults.NameClaimType;
    public string? RoleClaimType { get; set; } = AuthProxyConstants.Defaults.RoleClaimType;
}