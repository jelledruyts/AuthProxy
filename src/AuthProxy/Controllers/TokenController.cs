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
        var identityProvider = this.identityProviderFactory.GetIdentityProvider(request.IdentityProvider);
        if (identityProvider == null)
        {
            return BadRequest();
        }
        return await identityProvider.GetTokenAsync(this.HttpContext, request);
    }
}