using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class CallApiModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    private readonly IHttpClientFactory httpClientFactory;
    [BindProperty]
    public string? IdentityProvider { get; set; } = "aad";
    [BindProperty]
    public string? Scopes { get; set; } = "user.read";
    public string? Result { get; set; }

    public CallApiModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
    }

    public async Task<IActionResult> OnPostGetToken()
    {
        try
        {
            var httpClient = this.httpClientFactory.CreateClient();
            var request = new
            {
                IdentityProvider = this.IdentityProvider,
                Scopes = this.Scopes?.Split(" "),
                ReturnUrl = this.HttpContext.Request.GetEncodedUrl()
            };
            var authorizationValue = this.HttpContext.Request.Headers["X-AuthProxy-API-token"].FirstOrDefault();
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", authorizationValue);
            var responseMessage = await httpClient.PostAsync("https://localhost:7268/.auth/api/token", JsonContent.Create(request));
            var responseBody = await responseMessage.Content.ReadAsStringAsync();
            if (!responseMessage.IsSuccessStatusCode)
            {
                this.Result = responseMessage.StatusCode.ToString() + ". " + responseBody;
            }
            else
            {
                var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseBody, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (!string.IsNullOrWhiteSpace(tokenResponse?.RedirectUrl))
                {
                    if (tokenResponse.RedirectCookies != null)
                    {
                        Response.Headers.SetCookie = tokenResponse.RedirectCookies;
                    }
                    return Redirect(tokenResponse.RedirectUrl);
                }
                this.Result = tokenResponse?.Token;
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

    private class TokenResponse
    {
        public string? Status { get; set; }
        public string? Token { get; set; }
        public string? RedirectUrl { get; set; }
        public string[]? RedirectCookies { get; set; }
    }
}