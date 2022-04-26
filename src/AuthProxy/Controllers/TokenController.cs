using AuthProxy.IdentityProviders;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthProxy.Controllers;

[ApiController]
[Route("[basepath]/[controller]")]
[Authorize(AuthenticationSchemes = Constants.AuthenticationSchemes.AuthProxy)]
public class TokenController : ControllerBase
{
    private readonly IdentityProviderFactory identityProviderFactory;

    public TokenController(IdentityProviderFactory identityProviderFactory)
    {
        this.identityProviderFactory = identityProviderFactory;
    }

    [HttpPost]
    public async Task<ActionResult<TokenResponse>> GetTokenAsync(TokenRequest request)
    {
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