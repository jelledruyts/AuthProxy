using System.Net.Http.Headers;
using AuthProxy.Configuration;

namespace AuthProxy.Infrastructure.ReverseProxy;

public class ExternalServiceYarpHttpTransformer : BaseHttpTransformer
{
    public const string ContextItemKeyRequestUri = "X-AuthProxy-RequestUri";
    public const string ContextItemKeyOutboundPolicyAction = "X-AuthProxy-OutboundPolicyAction";
    public const string ContextItemKeyToken = "X-AuthProxy-Token";

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);

        // Set the target URI to the requested destination.
        proxyRequest.RequestUri = (Uri)httpContext.Items[ContextItemKeyRequestUri]!;
        var outboundPolicyAction = (OutboundPolicyAction)httpContext.Items[ContextItemKeyOutboundPolicyAction]!;
        var token = (string)httpContext.Items[ContextItemKeyToken]!;
        if (outboundPolicyAction == OutboundPolicyAction.AttachBearerToken)
        {
            // Attach the bearer token to the outgoing request.
            proxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
    }
}