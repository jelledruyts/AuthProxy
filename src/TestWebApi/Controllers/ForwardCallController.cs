using AuthProxy.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestWebApi.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class ForwardCallController : ControllerBase
{
    private readonly ILogger<IdentityController> logger;
    private readonly IHttpClientFactory httpClientFactory;

    public ForwardCallController(ILogger<IdentityController> logger, IHttpClientFactory httpClientFactory)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
    }

    [HttpPost]
    public async Task<string> ForwardCallAsync(string destinationUrl)
    {
        // Get a preconfigured HTTP client which has an HTTP message handler injected that can automatically
        // transform a regular HTTP request into a request towards the proxy's Forward API.
        var httpClient = this.httpClientFactory.CreateForwardApiHttpClient();

        // Use the HTTP client as if it represented the actual API, in this case by performing a GET
        // but this could be using any method, headers and body.
        return await httpClient.GetStringAsync(destinationUrl);
    }
}