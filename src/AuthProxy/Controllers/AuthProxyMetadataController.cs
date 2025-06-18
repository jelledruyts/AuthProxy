using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthProxy.Controllers;

[ApiController]
[Authorize(AuthenticationSchemes = Constants.AuthenticationSchemes.AuthProxy)]
public class AuthProxyMetadataController : ControllerBase
{
    private readonly AuthProxyConfigMetadata authProxyMetadata;

    public AuthProxyMetadataController(AuthProxyConfig authProxyConfig, IdentityProviderFactory identityProviderFactory)
    {
        this.authProxyMetadata = new AuthProxyConfigMetadata
        {
            Authentication = new AuthenticationConfigMetadata
            {
                DefaultIdentityProvider = authProxyConfig.Authentication.DefaultIdentityProvider,
                LogoutPath = authProxyConfig.Authentication.LogoutPath,
                LoginPath = authProxyConfig.Authentication.LoginPath,
                IdentityProviders = authProxyConfig.Authentication.IdentityProviders
                    .Select(i => new IdentityProviderConfigMetadata
                    {
                        Id = i.Id,
                        Type = i.Type,
                        DisplayName = i.DisplayName,
                        // Get the login path from the identity provider factory, which ensures that the path is correctly configured.
                        LoginPath = identityProviderFactory.IdentityProviders.LastOrDefault(p => p.Configuration.Id == i.Id)?.LoginPath
                    })
                    .ToList(),
                TokenRequestProfiles = authProxyConfig.Authentication.TokenRequestProfiles
                    .Select(t => new TokenRequestProfileConfigMetadata
                    {
                        Id = t.Id,
                        IdentityProvider = t.IdentityProvider
                    })
                    .ToList()
            }
        };
    }

    [Route(AuthProxyConstants.UrlPaths.AuthProxyConfiguration)]
    public ActionResult GetAuthProxyConfiguration()
    {
        return Ok(this.authProxyMetadata);
    }
}