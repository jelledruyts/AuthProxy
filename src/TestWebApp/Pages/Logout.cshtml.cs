using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class LogoutModel : PageModel
{
    public void OnGet()
    {
        // Communicate back to the Auth Proxy using response headers.
        this.Response.Headers.Append("X-AuthProxy-Action", "logout");
        this.Response.Headers.Append("X-AuthProxy-ReturnUrl", "/privacy");
    }
}