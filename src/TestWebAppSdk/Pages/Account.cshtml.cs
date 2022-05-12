using Microsoft.AspNetCore.Mvc.RazorPages;
using TestWebApp.Models;

namespace TestWebApp.Pages;

public class AccountModel : PageModel
{
    private readonly ILogger<AccountModel> logger;
    public IList<InspectorValue>? IdentityInfo { get; set; }
    public IList<InspectorValue>? ClaimsInfo { get; set; }

    public AccountModel(ILogger<AccountModel> logger)
    {
        this.logger = logger;
    }

    public void OnGet()
    {
        this.IdentityInfo = InspectorValue.GetIdentityInfo(this.User);
        this.ClaimsInfo = InspectorValue.GetClaimsInfo(this.User);
    }
}