using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class CallApiModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    [BindProperty]
    public string? TokenRequestIdentityProvider { get; set; } = "aad";
    [BindProperty]
    public string? TokenRequestScopes { get; set; } = "user.read";
    [BindProperty]
    public Actor TokenRequestActor { get; set; } = Actor.User;
    public string? InfoMessage { get; set; }
    public string? Result { get; set; }

    public CallApiModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
        this.jsonSerializerOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        this.jsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public void OnGet()
    {
        // If the return URL was invoked with query string parameters to remember the original
        // request, re-populate the form with those original values.
        this.TokenRequestIdentityProvider = this.Request.Query[nameof(TokenRequest.IdentityProvider)].FirstOrDefault() ?? this.TokenRequestIdentityProvider;
        this.TokenRequestScopes = this.Request.Query[nameof(TokenRequest.Scopes)].FirstOrDefault() ?? this.TokenRequestScopes;
        this.InfoMessage = this.Request.Query[nameof(TokenRequest.IdentityProvider)].Any() ? "We had to sign you back in first. Please retry the request." : null;
    }

    public async Task<IActionResult> OnPostGetToken()
    {
        try
        {
            // Prepare the token request for the Auth Proxy API.
            var request = new TokenRequest
            {
                IdentityProvider = this.TokenRequestIdentityProvider,
                Scopes = this.TokenRequestScopes?.Split(" "),
                Actor = this.TokenRequestActor,
                // If a redirect would be necessary, return back to this page with additional query parameters to remember the original request values.
                ReturnUrl = this.Url.Page("CallApi", null, new { IdentityProvider = this.TokenRequestIdentityProvider, Scopes = this.TokenRequestScopes }, this.HttpContext.Request.Scheme, this.HttpContext.Request.Host.Value)
            };

            // Retrieve the authorization token that Auth Proxy provided to call back into its own API.
            var httpClient = this.httpClientFactory.CreateClient();
            var authorizationValue = this.HttpContext.Request.Headers["X-AuthProxy-API-token"].FirstOrDefault();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authorizationValue);

            // Perform the API call towards Auth Proxy.
            var responseMessage = await httpClient.PostAsync("https://localhost:7268/.auth/api/token", JsonContent.Create(request));
            var responseBody = await responseMessage.Content.ReadAsStringAsync();

            // Check the API response.
            if (!responseMessage.IsSuccessStatusCode)
            {
                // Something went wrong while calling the API itself.
                this.Result = responseMessage.StatusCode.ToString() + ". " + responseBody;
            }
            else
            {
                // The API responded, check the result.
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody, jsonSerializerOptions);
                if (tokenResponse?.Status == TokenResponseStatus.RedirectRequired)
                {
                    // The token request could not be completed, user interaction via a redirect was required.
                    if (tokenResponse.RedirectCookies != null)
                    {
                        // The redirect flow requires additional cookies to be set, return them back to the browser.
                        Response.Headers.SetCookie = tokenResponse.RedirectCookies.ToArray();
                    }

                    // Issue a redirect to the requested URL.
                    return Redirect(tokenResponse.RedirectUrl!);
                }
                else if (tokenResponse?.Status == TokenResponseStatus.Succeeded)
                {
                    // The token request succeeded, output the token itself (in a real world scenario, the token would
                    // be used to call a backend API of course).
                    this.Result = tokenResponse?.Token;
                }
            }
        }
        catch (Exception exc)
        {
            this.Result = exc.ToString();
        }
        return Page();
    }

    public async Task OnPostDirectCall()
    {
        try
        {
            var httpClient = this.httpClientFactory.CreateClient();
            // this.GraphResult = await httpClient.GetStringAsync("https://graph.microsoft.com/v1.0/users/me");
            this.Result = await httpClient.GetStringAsync("http://ipinfo.io/ip");
        }
        catch (Exception exc)
        {
            this.Result = exc.ToString();
        }
    }

    // Local copy of the models (ultimately this could live in a client SDK along with helpers).

    public enum Actor
    {
        User,
        App,
        AzureManagedIdentity
    }

    public class TokenRequest
    {
        public string? IdentityProvider { get; set; } // TODO-M: If empty: use default IdP
        public IList<string>? Scopes { get; set; }
        public string? ReturnUrl { get; set; } // If a redirect is required, determines where to redirect back after the interaction completed.
        public Actor Actor { get; set; }
    }

    public enum TokenResponseStatus
    {
        Succeeded,
        RedirectRequired
    }

    public class TokenResponse
    {
        public TokenResponseStatus Status { get; set; }
        public string? Token { get; set; }
        public string? RedirectUrl { get; set; }
        public IList<string>? RedirectCookies { get; set; }
    }
}