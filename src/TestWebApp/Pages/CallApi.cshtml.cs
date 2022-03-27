using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class CallApiModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    private readonly IHttpClientFactory httpClientFactory;
    public string? Result { get; set; }

    public CallApiModel(ILogger<IndexModel> logger, IHttpClientFactory httpClientFactory)
    {
        this.logger = logger;
        this.httpClientFactory = httpClientFactory;
    }

    public async Task OnPost()
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
}
