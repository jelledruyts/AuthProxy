using System.Net.Http.Headers;
using AuthProxy.ReverseProxy.Configuration;

namespace AuthProxy.ReverseProxy.Infrastructure.ReverseProxy;

public class ExternalServiceYarpHttpTransformer : BaseHttpTransformer
{
    public const string ContextItemKeyRequestUri = "X-AuthProxy-RequestUri";
    public const string ContextItemKeyOutboundPolicyAction = "X-AuthProxy-OutboundPolicyAction";
    public const string ContextItemKeyToken = "X-AuthProxy-Token";

    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix, CancellationToken cancellationToken)
    {
        // Perform default behavior.
        await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

        // Set the target URI to the requested destination.
        proxyRequest.RequestUri = (Uri)httpContext.Items[ContextItemKeyRequestUri]!;
        if (httpContext.Items.ContainsKey(ContextItemKeyOutboundPolicyAction))
        {
            var outboundPolicyAction = (OutboundPolicyAction)httpContext.Items[ContextItemKeyOutboundPolicyAction]!;
            if (outboundPolicyAction == OutboundPolicyAction.AttachBearerToken)
            {
                // Attach the bearer token to the outgoing request.
                var token = (string)httpContext.Items[ContextItemKeyToken]!;
                proxyRequest.Headers.Authorization = new AuthenticationHeaderValue(Constants.HttpHeaders.Bearer, token);
            }
        }
    }
}