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
    public string? TokenRequestProfile { get; set; }
    [BindProperty]
    public string? TokenRequestIdentityProvider { get; set; }
    [BindProperty]
    public string? TokenRequestScopes { get; set; }
    [BindProperty]
    public Actor TokenRequestActor { get; set; } = Actor.User;
    [BindProperty]
    public string? ForwardCallDestinationUrl { get; set; }
    public string? InfoMessage { get; set; }
    public string? GetTokenResult { get; set; }
    public string? ErrorMessage { get; set; }
    public string? ForwardCallResult { get; set; }
    public IList<string> AvailableTokenRequestProfiles { get; set; } = new List<string>();
    public IList<string> AvailableIdentityProviders { get; set; } = new List<string>();

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

    public async Task OnGet()
    {
        await GetMetadataAsync();

        // If the return URL was invoked with query string parameters to remember the original
        // request, re-populate the form with those original values.
        this.InfoMessage = this.Request.Query[nameof(TokenRequestProfile)].Any() || this.Request.Query[nameof(TokenRequestIdentityProvider)].Any() || this.Request.Query[nameof(ForwardCallDestinationUrl)].Any() ? "We had to sign you back in first. Please retry the request." : null;
        this.TokenRequestProfile = this.Request.Query[nameof(TokenRequestProfile)].FirstOrDefault() ?? this.TokenRequestProfile;
        this.TokenRequestIdentityProvider = this.Request.Query[nameof(TokenRequestIdentityProvider)].FirstOrDefault() ?? this.TokenRequestIdentityProvider;
        this.TokenRequestScopes = this.Request.Query[nameof(TokenRequestScopes)].FirstOrDefault() ?? this.TokenRequestScopes;
        this.TokenRequestActor = this.Request.Query[nameof(TokenRequestActor)].FirstOrDefault() != null ? Enum.Parse<Actor>(this.Request.Query[nameof(TokenRequestActor)].FirstOrDefault()!) : this.TokenRequestActor;
        this.ForwardCallDestinationUrl = this.Request.Query[nameof(ForwardCallDestinationUrl)].FirstOrDefault() ?? this.ForwardCallDestinationUrl;
    }

    public async Task<IActionResult> OnPostGetTokenUsingProfile()
    {
        await GetMetadataAsync();
        var request = new TokenRequest
        {
            Profile = this.TokenRequestProfile
        };
        return await this.GetToken(request);
    }

    public async Task<IActionResult> OnPostGetTokenManual()
    {
        await GetMetadataAsync();
        var request = new TokenRequest
        {
            IdentityProvider = this.TokenRequestIdentityProvider,
            Actor = this.TokenRequestActor,
            Scopes = this.TokenRequestScopes?.Split(" ")
        };
        return await this.GetToken(request);
    }

    public async Task<IActionResult> OnPostForwardCall()
    {
        await GetMetadataAsync();
        try
        {
            // If a redirect would be necessary, make the redirect URL return back to this page
            // with additional query parameters to remember the original request values.
            var returnUrl = this.Url.Page("CallApi", null, new
            {
                ForwardCallDestinationUrl = this.ForwardCallDestinationUrl
            });

            // Rather than going directly towards the destination URL, call the proxy's Forward API instead.
            var httpClient = GetApiClient();
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-Destination", this.ForwardCallDestinationUrl);
            httpClient.DefaultRequestHeaders.Add("X-AuthProxy-ReturnUrl", returnUrl);
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

    private HttpClient GetApiClient()
    {
        // Get an HTTP client to call the proxy's API.
        var httpClient = this.httpClientFactory.CreateClient();
        httpClient.BaseAddress = this.authProxyBaseUrl;

        // Add the callback headers that Auth Proxy provided to call back into its own API.
        const string CallbackHeaderPrefix = "X-AuthProxy-Callback-Header-";
        foreach (var header in this.HttpContext.Request.Headers.Where(h => h.Key.StartsWith(CallbackHeaderPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            httpClient.DefaultRequestHeaders.Add(header.Key.Substring(CallbackHeaderPrefix.Length), header.Value.ToArray());
        }

        return httpClient;
    }

    private async Task GetMetadataAsync()
    {
        // Get the proxy's configuration metadata.
        var httpClient = GetApiClient();
        var metadata = await httpClient.GetFromJsonAsync<JsonElement>("/.well-known/authproxy-configuration", this.jsonSerializerOptions);
        var authenticationMetadata = metadata.GetProperty("authentication");
        foreach (var identityProvider in authenticationMetadata.GetProperty("identityProviders").EnumerateArray())
        {
            var id = identityProvider.GetProperty("id").GetString();
            if (!string.IsNullOrEmpty(id))
            {
                this.AvailableIdentityProviders.Add(id);
            }
        }
        foreach (var profile in authenticationMetadata.GetProperty("tokenRequestProfiles").EnumerateArray())
        {
            var id = profile.GetProperty("id").GetString();
            if (!string.IsNullOrEmpty(id))
            {
                this.AvailableTokenRequestProfiles.Add(id);
            }
        }
    }

    private async Task<IActionResult> GetToken(TokenRequest request)
    {
        try
        {
            // If a redirect would be necessary, make the redirect URL return back to this page
            // with additional query parameters to remember the original request values.
            request.ReturnUrl = this.Url.Page("CallApi", null, new
            {
                TokenRequestProfile = this.TokenRequestProfile,
                TokenRequestIdentityProvider = this.TokenRequestIdentityProvider,
                TokenRequestScopes = this.TokenRequestScopes
            });

            // Perform the API call towards Auth Proxy.
            var httpClient = GetApiClient();
            var tokenApiPath = this.HttpContext.Request.Headers["X-AuthProxy-Callback-TokenEndpoint"].First(); // Retrieve the path to the Token API from the headers to avoid hard-coding it.
            var responseMessage = await httpClient.PostAsync(tokenApiPath, JsonContent.Create(request, null, jsonSerializerOptions));
            var responseBody = await responseMessage.Content.ReadAsStringAsync();

            // Check the API response.
            if (!responseMessage.IsSuccessStatusCode)
            {
                // Something went wrong while calling the API itself.
                this.ErrorMessage = responseMessage.StatusCode.ToString() + ". " + responseBody;
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
                else if (tokenResponse?.Status == TokenResponseStatus.Failed)
                {
                    // The token request failed, show the error message.
                    this.ErrorMessage = tokenResponse?.ErrorMessage;
                }
            }
        }
        catch (Exception exc)
        {
            this.ErrorMessage = exc.ToString();
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
        Failed,
        RedirectRequired
    }

    public class TokenResponse
    {
        public TokenResponseStatus Status { get; set; }
        public string? Token { get; set; }
        public string? ErrorMessage { get; set; }
        public string? RedirectUrl { get; set; }
        public IList<string>? RedirectCookies { get; set; }
    }
}