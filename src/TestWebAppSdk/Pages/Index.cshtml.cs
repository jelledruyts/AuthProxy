using Microsoft.AspNetCore.Mvc.RazorPages;
using TestWebApp.Models;

namespace TestWebApp.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> logger;
    public IList<InspectorValue>? RequestInfo { get; set; }
    public IList<InspectorValue>? HttpHeadersInfo { get; set; }
    public IList<InspectorValue>? IdentityInfo { get; set; }
    public IList<InspectorValue>? ClaimsInfo { get; set; }

    public IndexModel(ILogger<IndexModel> logger)
    {
        this.logger = logger;
    }

    public void OnGet()
    {
        this.RequestInfo = InspectorValue.GetRequestInfo(this.Request);
        this.HttpHeadersInfo = InspectorValue.GetHttpHeadersInfo(this.Request);
        this.IdentityInfo = InspectorValue.GetIdentityInfo(this.User);
        this.ClaimsInfo = InspectorValue.GetClaimsInfo(this.User);
    }
}