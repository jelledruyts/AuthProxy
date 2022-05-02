using AuthProxy.Configuration;

namespace AuthProxy.IdentityProviders;

public class IdentityProviderFactory
{
    private readonly AuthProxyConfig authProxyConfig;
    public IList<IdentityProvider> IdentityProviders { get; } = new List<IdentityProvider>();
    public IdentityProvider? DefaultIdentityProvider { get; }

    public IdentityProviderFactory(AuthProxyConfig authProxyConfig)
    {
        this.authProxyConfig = authProxyConfig;
        // TODO: Ensure IdentityProvider's Name is acceptable in URLs, unique across other IdPs and does not conflict with the default authentication scheme (Defaults.AuthenticationScheme)
        // TODO: Ensure IdentityProvider's callback paths are unique across all configured IdPs and don't conflict with the default paths.
        if (authProxyConfig.Authentication.IdentityProviders != null && authProxyConfig.Authentication.IdentityProviders.Any())
        {
            var postLoginReturnUrlQueryParameterName = authProxyConfig.Authentication.PostLoginReturnUrlQueryParameterName;

            // Add an authentication service for each IdP (e.g. "/.auth/login/<name>").
            foreach (var identityProviderConfig in authProxyConfig.Authentication.IdentityProviders)
            {
                ArgumentNullException.ThrowIfNull(identityProviderConfig.Name);
                var authenticationScheme = identityProviderConfig.Name;
                var loginPath = GetLoginPath(identityProviderConfig);
                var loginCallbackPath = GetLoginCallbackPath(identityProviderConfig);
                var identityProvider = CreateIdentityProvider(identityProviderConfig, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName);
                this.IdentityProviders.Add(identityProvider);
            }

            var defaultIdentityProvider = this.IdentityProviders.FirstOrDefault(i => string.Equals(i.Configuration.Name, authProxyConfig.Authentication.DefaultIdentityProvider, StringComparison.OrdinalIgnoreCase));
            if (defaultIdentityProvider != null)
            {
                // Add an authentication service for the default IdP (e.g. "/.auth/login").
                // Note that it was already added before, but in order to get a clean URL for the case where
                // there's only a single IdP, it has to be added specifically as the login callback path
                // has to be unique for each registered authentication service.
                var defaultAuthenticationScheme = Defaults.AuthenticationScheme;
                var defaultLoginPath = GetDefaultLoginPath();
                var defaultLoginCallbackPath = GetDefaultLoginCallbackPath();
                this.DefaultIdentityProvider = CreateIdentityProvider(defaultIdentityProvider.Configuration, defaultAuthenticationScheme, defaultLoginPath, defaultLoginCallbackPath, postLoginReturnUrlQueryParameterName);
                this.IdentityProviders.Insert(0, this.DefaultIdentityProvider);
            }
        }
    }

    private IdentityProvider CreateIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
    {
        if (configuration.Type == IdentityProviderType.OpenIdConnect)
        {
            return new OpenIdConnectIdentityProvider(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName);
        }
        else if (configuration.Type == IdentityProviderType.AzureAD)
        {
            return new AzureADIdentityProvider(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName);
        }
        else if (configuration.Type == IdentityProviderType.AzureADB2C)
        {
            return new AzureADB2CIdentityProvider(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName);
        }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(configuration.Type), $"Unknown {nameof(IdentityProviderType)}: \"{configuration.Type.ToString()}\".");
        }
    }

    public IdentityProvider? GetIdentityProvider(string? name)
    {
        return this.IdentityProviders.FirstOrDefault(i => i.Configuration.Name == name);
    }

    private string GetDefaultLoginPath()
    {
        return this.authProxyConfig.Authentication.LoginPath;
    }

    private string GetLoginPath(IdentityProviderConfig identityProvider)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Name);
        return GetPath(GetDefaultLoginPath(), identityProvider.LoginPath, identityProvider.Name);
    }

    private string GetDefaultLoginCallbackPath()
    {
        return this.authProxyConfig.Authentication.LoginCallbackPath;
    }

    private string GetLoginCallbackPath(IdentityProviderConfig identityProvider)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Name);
        return GetPath(GetDefaultLoginCallbackPath(), identityProvider.LoginCallbackPath, identityProvider.Name);
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