using AuthProxy.Client;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace TestWebApp.Pages;

public class LogoutModel : PageModel
{
    public void OnGet()
    {
        // Communicate back to the Auth Proxy using response headers.
        var returnUrl = this.Url.Page("Privacy");
        this.Response.SignalAuthProxyLogout(returnUrl);
    }
}