using AuthProxy.Configuration;
using AuthProxy.IdentityProviders;
using AuthProxy.Infrastructure;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthProxy.Controllers;

// TODO: Make configurable whether or not to enable this API as this increases the attack surface of the proxy.
[ApiController]
[Route(ApiRoutingConvention.Placeholder + "/" + Constants.ApiPaths.Token)]
[Authorize(AuthenticationSchemes = Constants.AuthenticationSchemes.AuthProxy)]
public class TokenController : ControllerBase
{
    private readonly AuthProxyConfig authProxyConfig;
    private readonly IdentityProviderFactory identityProviderFactory;

    public TokenController(AuthProxyConfig authProxyConfig, IdentityProviderFactory identityProviderFactory)
    {
        this.authProxyConfig = authProxyConfig;
        this.identityProviderFactory = identityProviderFactory;
    }

    [HttpPost]
    public async Task<ActionResult<TokenResponse>> GetTokenAsync(TokenRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.Profile))
        {
            // A configured token request profile was requested, look it up.
            var profile = this.authProxyConfig.Authentication.TokenRequestProfiles.FirstOrDefault(p => string.Equals(p.Name, request.Profile, StringComparison.OrdinalIgnoreCase));
            if (profile == null)
            {
                return BadRequest();
            }
            // Replace unspecified properties (and only those) in the request with configured properties of the profile.
            request.Actor ??= profile.Actor;
            request.IdentityProvider ??= profile.IdentityProvider;
            request.ReturnUrl ??= profile.ReturnUrl;
            request.Scopes ??= profile.Scopes;
        }

        var identityProvider = default(IdentityProvider);
        if (request.IdentityProvider == null)
        {
            // No identity provider was explicitly requested, which implies to use the default identity provider.
            identityProvider = this.identityProviderFactory.DefaultIdentityProvider;
        }
        else
        {
            // Look up the requested identity provider.
            identityProvider = this.identityProviderFactory.GetIdentityProvider(request.IdentityProvider);
        }
        if (identityProvider == null)
        {
            return BadRequest();
        }

        // Request a token from the identity provider.
        return await identityProvider.GetTokenAsync(this.HttpContext, request);
    }
}