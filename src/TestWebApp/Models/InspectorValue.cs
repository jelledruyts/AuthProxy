using System.Security.Claims;
using Microsoft.AspNetCore.Http.Extensions;

namespace TestWebApp.Models;

public class InspectorValue
{
    public string Key { get; set; }
    public string DisplayName { get; set; }
    public object? Value { get; set; }

    public InspectorValue(string key, string displayName, object? value)
    {
        this.Key = key;
        this.DisplayName = displayName;
        this.Value = value;
    }

    public static IList<InspectorValue> GetRequestInfo(HttpRequest request)
    {
        var info = new List<InspectorValue>();
        info.Add(new InspectorValue("request-url", "URL", UriHelper.GetDisplayUrl(request)));
        info.Add(new InspectorValue("request-method", "HTTP Method", request.Method));
        info.Add(new InspectorValue("request-ishttps", "Is HTTPS", request.IsHttps));
        info.Add(new InspectorValue("request-id", "Request ID", request.HttpContext.TraceIdentifier));
        info.Add(new InspectorValue("clientcertificate-serialnumber", "Client Certificate Serial Number", request.HttpContext.Connection.ClientCertificate?.SerialNumber));
        info.Add(new InspectorValue("local-ipaddress", "Local IP Address", request.HttpContext.Connection.LocalIpAddress?.ToString()));
        info.Add(new InspectorValue("local-port", "Local Port", request.HttpContext.Connection.LocalPort));
        info.Add(new InspectorValue("remote-ipaddress", "Remote IP Address", request.HttpContext.Connection.RemoteIpAddress?.ToString()));
        info.Add(new InspectorValue("remote-port", "Remote Port", request.HttpContext.Connection.RemotePort));
        return info;
    }

    public static IList<InspectorValue> GetHttpHeadersInfo(HttpRequest request)
    {
        var info = new List<InspectorValue>();
        foreach (var item in request.Headers.OrderBy(k => k.Key))
        {
            foreach (var value in request.Headers[item.Key])
            {
                info.Add(new InspectorValue(item.Key, item.Key, value));
            }
        }
        return info;
    }

    public static IList<InspectorValue> GetIdentityInfo(ClaimsPrincipal user)
    {
        var info = new List<InspectorValue>();
        if (user.Identity != null)
        {
            info.Add(new InspectorValue("user-name", "User Name", user.Identity.Name));
            info.Add(new InspectorValue("user-isauthenticated", "User Is Authenticated", user.Identity.IsAuthenticated));
            info.Add(new InspectorValue("user-authenticationtype", "User Authentication Type", user.Identity.AuthenticationType));
        }
        return info;
    }

    public static IList<InspectorValue> GetClaimsInfo(ClaimsPrincipal user)
    {
        var info = new List<InspectorValue>();
        if (user.Identity is ClaimsIdentity identity)
        {
            foreach (var claim in identity.Claims.OrderBy(c => c.Type))
            {
                info.Add(new InspectorValue("user-claim-" + claim.Type, claim.Type, claim.Value));
            }
        }
        return info;
    }
}