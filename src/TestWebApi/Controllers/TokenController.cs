using AuthProxy.Client;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestWebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly ILogger<IdentityController> logger;
    private readonly AuthProxyApiService authProxyApiService;

    public TokenController(ILogger<IdentityController> logger, AuthProxyApiService authProxyApiService)
    {
        this.logger = logger;
        this.authProxyApiService = authProxyApiService;
    }

    [HttpPost]
    public async Task<TokenResponse> GetTokenAsync(TokenRequest request)
    {
        return await this.authProxyApiService.GetTokenAsync(request);
    }
}