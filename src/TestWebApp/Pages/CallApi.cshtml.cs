using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Primitives;

namespace TestWebApp.Pages;

public class CallApiModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    private readonly IHttpClientFactory httpClientFactory;
    private readonly Uri authProxyBaseUrl;
    private readonly JsonSerializerOptions jsonSerializerOptions;
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

    public CallApiModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
        this.authProxyBaseUrl = new Uri(configuration.GetValue<string>("AuthProxyBaseUrl"));
        this.jsonSerializerOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        this.jsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
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
        try
        {
            // Prepare the token request for the Auth Proxy API.
            var request = new TokenRequest
            {
                // If a redirect would be necessary, make the redirect URL return back to this page with additional query parameters to remember the original request values.
                ReturnUrl = this.Url.Page("CallApi", null, new
                {
                    TokenRequestProfile = this.TokenRequestProfile,
                    TokenRequestIdentityProvider = this.TokenRequestIdentityProvider,
                    TokenRequestScopes = this.TokenRequestScopes
                }, this.HttpContext.Request.Scheme, this.HttpContext.Request.Host.Value)
            };
            if (!string.IsNullOrWhiteSpace(this.TokenRequestProfile))
            {
                // A token request profile was request, don't specify the other properties.
                request.Profile = this.TokenRequestProfile;
            }
            else
            {
                request.IdentityProvider = this.TokenRequestIdentityProvider;
                request.Actor = this.TokenRequestActor;
                request.Scopes = this.TokenRequestScopes?.Split(" ");
            }

            // Retrieve the authorization token that Auth Proxy provided to call back into its own API.
            var httpClient = this.httpClientFactory.CreateClient();
            httpClient.BaseAddress = this.authProxyBaseUrl;
            var authorizationHeaderName = this.HttpContext.Request.Headers["X-AuthProxy-API-AuthorizationHeader-Name"].First();
            var authorizationHeaderValue = this.HttpContext.Request.Headers["X-AuthProxy-API-AuthorizationHeader-Value"].First();
            httpClient.DefaultRequestHeaders.Add(authorizationHeaderName, authorizationHeaderValue);

            // Perform the API call towards Auth Proxy.
            var tokenApiPath = this.HttpContext.Request.Headers["X-AuthProxy-API-Path-Token"].First(); // Retrieve the path to the Token API from the headers to avoid hard-coding it.
            var responseMessage = await httpClient.PostAsync(tokenApiPath, JsonContent.Create(request));
            var responseBody = await responseMessage.Content.ReadAsStringAsync();

            // Check the API response.
            if (!responseMessage.IsSuccessStatusCode)
            {
                // Something went wrong while calling the API itself.
                this.GetTokenResult = responseMessage.StatusCode.ToString() + ". " + responseBody;
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
                    this.GetTokenResult = tokenResponse?.Token;
                }
            }
        }
        catch (Exception exc)
        {
            this.GetTokenResult = exc.ToString();
        }
        return Page();
    }

    public async Task<IActionResult> OnPostForwardCall()
    {
        try
        {
            var httpClient = this.httpClientFactory.CreateClient();
            httpClient.BaseAddress = this.authProxyBaseUrl;
            // If a redirect would be necessary, make the redirect URL return back to this page with additional query parameters to remember the original request values.
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-ReturnUrl", this.Url.Page("CallApi", null, new { ForwardCallDestinationUrl = this.ForwardCallDestinationUrl }, this.HttpContext.Request.Scheme, this.HttpContext.Request.Host.Value));
            var authorizationHeaderName = this.HttpContext.Request.Headers["X-AuthProxy-API-AuthorizationHeader-Name"].First();
            var authorizationHeaderValue = this.HttpContext.Request.Headers["X-AuthProxy-API-AuthorizationHeader-Value"].First();
            httpClient.DefaultRequestHeaders.Add(authorizationHeaderName, authorizationHeaderValue);
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-Destination", this.ForwardCallDestinationUrl);
            var forwardApiPath = this.HttpContext.Request.Headers["X-AuthProxy-API-Path-Forward"].First(); // Retrieve the path to the Forward API from the headers to avoid hard-coding it.
            var responseMessage = await httpClient.GetAsync(forwardApiPath);
            var responseBody = await responseMessage.Content.ReadAsStringAsync();

            // Check the API response.
            if (responseMessage.StatusCode == HttpStatusCode.NetworkAuthenticationRequired)
            {
                // The request could not be forwarded, check response headers for status.
                if (responseMessage.Headers.Contains("X-AuthProxy-Status"))
                {
                    var status = Enum.Parse<TokenResponseStatus>(responseMessage.Headers.GetValues("X-AuthProxy-Status").First());
                    if (status == TokenResponseStatus.RedirectRequired)
                    {
                        // The token request could not be completed, user interaction via a redirect was required.
                        var redirectUrl = responseMessage.Headers.GetValues("X-AuthProxy-RedirectUrl").FirstOrDefault();
                        var redirectCookies = responseMessage.Headers.GetValues("X-AuthProxy-RedirectCookies");
                        if (redirectCookies != null)
                        {
                            // The redirect flow requires additional cookies to be set, return them back to the browser.
                            Response.Headers.SetCookie = new StringValues(redirectCookies.ToArray());
                        }

                        // Issue a redirect to the requested URL.
                        return Redirect(redirectUrl!);
                    }
                }
            }
            else if (!responseMessage.IsSuccessStatusCode)
            {
                // Something went wrong while calling the API itself.
                this.ForwardCallResult = $"Error {responseMessage.StatusCode.ToString()}. {responseBody}";
            }
            else
            {
                // The request was forwarded successfully, output the response body.
                this.ForwardCallResult = responseBody;
            }
        }
        catch (Exception exc)
        {
            this.ForwardCallResult = exc.ToString();
        }
        return Page();
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
        public string? Profile { get; set; }
        public string? IdentityProvider { get; set; }
        public Actor? Actor { get; set; }
        public IList<string>? Scopes { get; set; }
        public string? ReturnUrl { get; set; }
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