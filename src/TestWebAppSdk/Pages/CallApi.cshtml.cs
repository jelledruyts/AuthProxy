using AuthProxy.Client;
using AuthProxy.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class CallApiModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly AuthProxyApiService authProxyApiService;
    [BindProperty]
    public string? TokenRequestProfile { get; set; } = "UserCallsGraph";
    [BindProperty]
    public string? TokenRequestIdentityProvider { get; set; }
    [BindProperty]
    public string? TokenRequestScopes { get; set; }
    [BindProperty]
    public Actor TokenRequestActor { get; set; } = Actor.User;
    [BindProperty]
    public string ForwardCallDestinationUrl { get; set; } = "https://graph.microsoft.com/v1.0/me";
    public string? InfoMessage { get; set; }
    public string? GetTokenResult { get; set; }
    public string? ForwardCallResult { get; set; }

    public CallApiModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, AuthProxyApiService authProxyApiService)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
        this.authProxyApiService = authProxyApiService;
    }

    public void OnGet()
    {
        // If the return URL was invoked with query string parameters to remember the original
        // request, re-populate the form with those original values.
        this.InfoMessage = this.Request.Query[nameof(TokenRequestProfile)].Any() || this.Request.Query[nameof(TokenRequestIdentityProvider)].Any() || this.Request.Query[nameof(ForwardCallDestinationUrl)].Any() ? "We had to sign you back in first. Please retry the request." : null;
        this.TokenRequestProfile = this.Request.Query[nameof(TokenRequestProfile)].FirstOrDefault() ?? this.TokenRequestProfile;
        this.TokenRequestIdentityProvider = this.Request.Query[nameof(TokenRequestIdentityProvider)].FirstOrDefault() ?? this.TokenRequestIdentityProvider;
        this.TokenRequestScopes = this.Request.Query[nameof(TokenRequestScopes)].FirstOrDefault() ?? this.TokenRequestScopes;
        this.TokenRequestActor = this.Request.Query[nameof(TokenRequestActor)].FirstOrDefault() != null ? Enum.Parse<Actor>(this.Request.Query[nameof(TokenRequestActor)].FirstOrDefault()!) : this.TokenRequestActor;
        this.ForwardCallDestinationUrl = this.Request.Query[nameof(ForwardCallDestinationUrl)].FirstOrDefault() ?? this.ForwardCallDestinationUrl;
    }

    public async Task<IActionResult> OnPostGetToken()
    {
        // If a redirect would be necessary, make the redirect URL return back to this page
        // with additional query parameters to remember the original request values.
        var returnUrl = this.Url.Page("CallApi", null, new
        {
            TokenRequestProfile = this.TokenRequestProfile,
            TokenRequestIdentityProvider = this.TokenRequestIdentityProvider,
            TokenRequestScopes = this.TokenRequestScopes
        });

        // Prepare the token request for the Auth Proxy API.
        var request = new TokenRequest { ReturnUrl = returnUrl };
        if (!string.IsNullOrWhiteSpace(this.TokenRequestProfile))
        {
            // A token request profile was requested, don't specify the other properties.
            request.Profile = this.TokenRequestProfile;
        }
        else
        {
            request.IdentityProvider = this.TokenRequestIdentityProvider;
            request.Actor = this.TokenRequestActor;
            request.Scopes = this.TokenRequestScopes?.Split(" ");
        }

        // Use the API client to perform the token request.
        var tokenResponse = await this.authProxyApiService.GetTokenAsync(request);

        // If the API call failed to acquire a token, the request would automatically get
        // transformed into a redirect back to the IdP (which then also allows to acquire the token).
        this.GetTokenResult = tokenResponse.Token;

        return Page();
    }

    public async Task<IActionResult> OnPostForwardCall()
    {
        // If a redirect would be necessary, make the redirect URL return back to this page
        // with additional query parameters to remember the original request values.
        var returnUrl = this.Url.Page("CallApi", null, new
        {
            ForwardCallDestinationUrl = this.ForwardCallDestinationUrl
        });

        // Get a preconfigured HTTP client which has an HTTP message handler injected that can automatically
        // transform a regular HTTP request into a request towards the proxy's Forward API.
        var httpClient = this.httpClientFactory.CreateForwardApiHttpClient(returnUrl);

        // Use the HTTP client as if it represented the actual API, in this case by performing a GET
        // but this could be using any method, headers and body.
        this.ForwardCallResult = await httpClient.GetStringAsync(this.ForwardCallDestinationUrl);

        // If the API call failed to acquire a token, the request would automatically get
        // transformed into a redirect back to the IdP (which then also allows to acquire the token).

        return Page();
    }
}