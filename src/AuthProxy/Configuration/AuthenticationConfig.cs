namespace AuthProxy.Configuration;

public class AuthenticationConfig
{
    public CookieConfig? Cookie { get; set; }
    public TokenIssuerConfig? TokenIssuer { get; set; }
    public IList<IdentityProviderConfig>? IdentityProviders { get; set; }
    public IdentityProviderConfig? DefaultIdentityProvider => this.IdentityProviders?.FirstOrDefault();
    // TODO: Add "DefaultIdentityProviderName" configuration property to be explicit?
    // TODO: Add "AllowedExternalRedirectUrls" to validate post login/logout URLs etc

    public string GetDefaultAuthenticationScheme()
    {
        return Defaults.AuthenticationScheme;
    }

    public string GetDefaultLoginPath()
    {
        return Defaults.LoginPath; // TODO: Make this configurable.
    }

    public string GetLoginPath(IdentityProviderConfig identityProvider)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Name);
        return GetPath(GetDefaultLoginPath(), identityProvider.LoginPath, identityProvider.Name);
    }

    public string GetDefaultLoginCallbackPath()
    {
        return Defaults.LoginCallbackPath; // TODO: Make this configurable.
    }

    public string GetLoginCallbackPath(IdentityProviderConfig identityProvider)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Name);
        return GetPath(GetDefaultLoginCallbackPath(), identityProvider.LoginCallbackPath, identityProvider.Name);
    }

    public string GetLogoutPath()
    {
        return Defaults.LogoutPath; // TODO: Make this configurable.
    }

    private string GetPath(string defaultPath, string? identityProviderPath, string identityProviderName)
    {
        if (!string.IsNullOrWhiteSpace(identityProviderPath))
        {
            return identityProviderPath;
        }
        else
        {
            // TODO: Support a replacement pattern in the default path,
            // for example "/.auth/$(identityProviderName/)login" (note the '/')
            // or "/.auth/login-$(identityProviderName)" (note the missing '/').
            return defaultPath + "/" + identityProviderName;
        }
    }
}