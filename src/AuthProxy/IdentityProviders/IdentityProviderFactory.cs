using AuthProxy.Configuration;

namespace AuthProxy.IdentityProviders;

public class IdentityProviderFactory
{
    public IList<IdentityProvider> IdentityProviders { get; } = new List<IdentityProvider>();

    public IdentityProviderFactory(AuthProxyConfig authProxyConfig)
    {
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication);
        if (authProxyConfig.Authentication.IdentityProviders != null && authProxyConfig.Authentication.IdentityProviders.Any())
        {
            var postLoginReturnUrlQueryParameterName = Defaults.PostLoginReturnUrlQueryParameterName; // TODO: Make configurable.

            // Add an authentication service for the default IdP (e.g. "/.auth/login").
            // Note that it will be added again later on, but in order to get a clean URL for the case where
            // there's only a single IdP, it has to be added specifically as the login callback path
            // has to be unique for each registered authentication service.
            var defaultAuthenticationScheme = Defaults.AuthenticationScheme;
            var defaultLoginPath = GetDefaultLoginPath();
            var defaultLoginCallbackPath = GetDefaultLoginCallbackPath();
            AddIdentityProvider(authProxyConfig.Authentication.IdentityProviders.First(), defaultAuthenticationScheme, defaultLoginPath, defaultLoginCallbackPath, postLoginReturnUrlQueryParameterName);

            // Add an authentication service for each IdP (e.g. "/.auth/login/<name>").
            foreach (var identityProviderConfig in authProxyConfig.Authentication.IdentityProviders)
            {
                ArgumentNullException.ThrowIfNull(identityProviderConfig.Name);
                var authenticationScheme = identityProviderConfig.Name;
                var loginPath = GetLoginPath(identityProviderConfig);
                var loginCallbackPath = GetLoginCallbackPath(identityProviderConfig);
                AddIdentityProvider(identityProviderConfig, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName);
            }
        }
    }

    private void AddIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
    {
        // TODO: Ensure IdentityProvider's Name is acceptable in URLs, unique across other IdPs and does not conflict with the default authentication scheme (Defaults.AuthenticationScheme)
        // TODO: Ensure IdentityProvider's callback paths are unique across all configured IdPs and don't conflict with the default paths.
        if (configuration.Type == IdentityProviderType.OpenIdConnect)
        {
            this.IdentityProviders.Add(new OpenIdConnectIdentityProvider(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName));
        }
        else if (configuration.Type == IdentityProviderType.AzureAD)
        {
            this.IdentityProviders.Add(new AzureADIdentityProvider(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName));
        }
        // else if (identityProviderConfig.Type == IdentityProviderType.JwtBearer)
        // {
        //     this.IdentityProviders.Add(new AzureADIdentityProvider(identityProviderConfig));
        //     // authenticationBuilder.AddJwtBearer(options =>
        //     // {
        //     //     // TODO: Make configurable where the incoming JWT is found (for example, use a different HTTP header).
        //     //     // https://stackoverflow.com/questions/56857905/how-to-customize-bearer-header-keyword-in-asp-net-core-for-jwtbearer-and-system
        //     //     options.Authority = authProxyConfig.Authentication.IdentityProvider.Authority;
        //     // });
        // }
        else
        {
            throw new ArgumentOutOfRangeException(nameof(configuration.Type), $"Unknown {nameof(IdentityProviderType)}: \"{configuration.Type.ToString()}\".");
        }
    }
    
    public IdentityProvider GetIdentityProvider(string name)
    {
        var identityProvider = this.IdentityProviders.SingleOrDefault(i => i.Configuration.Name == name);
        if (identityProvider == null)
        {
            throw new ArgumentException($"The requested identity provider with name \"{name}\" was not found.", nameof(name));
        }
        return identityProvider;
    }

    private string GetDefaultLoginPath()
    {
        return Defaults.LoginPath; // TODO: Make this configurable.
    }

    private string GetLoginPath(IdentityProviderConfig identityProvider)
    {
        ArgumentNullException.ThrowIfNull(identityProvider.Name);
        return GetPath(GetDefaultLoginPath(), identityProvider.LoginPath, identityProvider.Name);
    }

    private string GetDefaultLoginCallbackPath()
    {
        return Defaults.LoginCallbackPath; // TODO: Make this configurable.
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