using System.Net;
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
        var authProxyBaseUrlValue = configuration.GetValue<string>("AuthProxy:BaseUrl");
        if (string.IsNullOrEmpty(authProxyBaseUrlValue))
        {
            throw new InvalidOperationException("The AuthProxy base URL is not configured.");
        }
        this.authProxyBaseUrl = new Uri(authProxyBaseUrlValue);
        this.jsonSerializerOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
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

            // Get an HTTP client to call the proxy's API.
            var httpClient = this.httpClientFactory.CreateClient();
            httpClient.BaseAddress = this.authProxyBaseUrl;

            // Retrieve the authorization header that Auth Proxy provided to call back into its own API.
            var authorizationHeaderName = this.HttpContext.Request.Headers["X-AuthProxy-Callback-AuthorizationHeader-Name"].First();
            var authorizationHeaderValue = this.HttpContext.Request.Headers["X-AuthProxy-Callback-AuthorizationHeader-Value"].First();
            if (string.IsNullOrEmpty(authorizationHeaderName) || string.IsNullOrEmpty(authorizationHeaderValue))
            {
                throw new InvalidOperationException("The authorization header name or value is missing.");
            }
            httpClient.DefaultRequestHeaders.Add(authorizationHeaderName, authorizationHeaderValue);

            // Perform the API call towards Auth Proxy.
            var tokenApiPath = this.HttpContext.Request.Headers["X-AuthProxy-Callback-TokenEndpoint"].First(); // Retrieve the path to the Token API from the headers to avoid hard-coding it.
            var responseMessage = await httpClient.PostAsync(tokenApiPath, JsonContent.Create(request, null, jsonSerializerOptions));
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
            // If a redirect would be necessary, make the redirect URL return back to this page
            // with additional query parameters to remember the original request values.
            var returnUrl = this.Url.Page("CallApi", null, new
            {
                ForwardCallDestinationUrl = this.ForwardCallDestinationUrl
            });

            // Get an HTTP client to call the destination service.
            var httpClient = this.httpClientFactory.CreateClient();

            // Retrieve the authorization header that Auth Proxy provided to call back into its own API.
            var authorizationHeaderName = this.HttpContext.Request.Headers["X-AuthProxy-Callback-AuthorizationHeader-Name"].First();
            var authorizationHeaderValue = this.HttpContext.Request.Headers["X-AuthProxy-Callback-AuthorizationHeader-Value"].First();
            if (string.IsNullOrEmpty(authorizationHeaderName) || string.IsNullOrEmpty(authorizationHeaderValue))
            {
                throw new InvalidOperationException("The authorization header name or value is missing.");
            }
            httpClient.DefaultRequestHeaders.Add(authorizationHeaderName, authorizationHeaderValue);

            // Rather than going directly towards the destination URL, call the proxy's Forward API instead.
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-Destination", this.ForwardCallDestinationUrl);
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-ReturnUrl", returnUrl);
            httpClient.BaseAddress = this.authProxyBaseUrl;
            var forwardApiPath = this.HttpContext.Request.Headers["X-AuthProxy-Callback-ForwardEndpoint"].First(); // Retrieve the path to the Forward API from the headers to avoid hard-coding it.
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

    // Local copy of the models (as we're not using the Client SDK here).

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