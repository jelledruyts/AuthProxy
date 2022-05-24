using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestWebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class IdentityController : ControllerBase
{
    private readonly ILogger<IdentityController> _logger;

    public IdentityController(ILogger<IdentityController> logger)
    {
        _logger = logger;
    }

    [HttpGet]
    public Dictionary<string, List<string>> Get()
    {
        return this.User.Claims.ToLookup(c => c.Type, c => c.Value).ToDictionary(c => c.Key, c => c.ToList());
    }
}