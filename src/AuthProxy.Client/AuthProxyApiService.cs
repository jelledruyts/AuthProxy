using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthProxy.Models;
using Microsoft.AspNetCore.Http;

namespace AuthProxy.Client;

public class AuthProxyApiService
{
    private readonly HttpClient httpClient;
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly JsonSerializerOptions jsonSerializerOptions;
    public bool AutoRedirectWhenRequired { get; set; }

    public AuthProxyApiService(HttpClient httpClient, IHttpContextAccessor httpContextAccessor, AuthProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.BaseUrl);
        this.httpClient = httpClient;
        this.httpContextAccessor = httpContextAccessor;
        this.AutoRedirectWhenRequired = options.AutoRedirectWhenRequired;
        this.httpClient.BaseAddress = new Uri(options.BaseUrl);
        this.jsonSerializerOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        };
        this.jsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    }

    public async Task<AuthProxyConfigMetadata> GetAuthProxyConfigurationAsync()
    {
        return await this.httpClient.GetFromJsonAsync<AuthProxyConfigMetadata>(AuthProxyConstants.UrlPaths.AuthProxyConfiguration, this.jsonSerializerOptions) ?? throw new InvalidOperationException("Failed to retrieve AuthProxy configuration.");
    }

    public async Task<TokenResponse> GetTokenAsync(TokenRequest request)
    {
        // Get the ambient HTTP context.
        var httpContext = this.httpContextAccessor.HttpContext;
        ArgumentNullException.ThrowIfNull(httpContext);

        // Retrieve the path to the Token API from the headers to avoid hard-coding it.
        var tokenApiPath = httpContext.Request.Headers[AuthProxyConstants.HttpHeaderNames.CallbackTokenEndpoint].First();

        // Perform the API call towards the proxy.
        var responseMessage = await this.httpClient.PostAsync(tokenApiPath, JsonContent.Create(request, null, jsonSerializerOptions));
        responseMessage.EnsureSuccessStatusCode();
        var responseBody = await responseMessage.Content.ReadAsStringAsync();

        // Check the API response.
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody, jsonSerializerOptions);
        ArgumentNullException.ThrowIfNull(tokenResponse);

        // If configured, check if a redirect is required.
        if (this.AutoRedirectWhenRequired)
        {
            // The token request could not be completed, user interaction via a redirect was required.
            if (tokenResponse.Status == TokenResponseStatus.RedirectRequired)
            {
                // Signal to the exception handler that a redirect is required.
                throw new AuthProxyTokenAcquisitionException(tokenResponse);
            }
        }
        return tokenResponse;
    }
}