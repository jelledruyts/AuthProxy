using Microsoft.AspNetCore.Http;

namespace AuthProxy.Client;

public class AuthProxyAuthorizationHttpMessageHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor httpContextAccessor;

    public AuthProxyAuthorizationHttpMessageHandler(IHttpContextAccessor httpContextAccessor, AuthProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.BaseUrl);
        this.httpContextAccessor = httpContextAccessor;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Get the ambient HTTP context.
        ArgumentNullException.ThrowIfNull(this.httpContextAccessor.HttpContext);
        var httpContext = this.httpContextAccessor.HttpContext;

        // Add the callback headers that Auth Proxy provided to call back into its own API.
        foreach (var header in httpContext.Request.Headers.Where(h => h.Key.StartsWith(AuthProxyConstants.HttpHeaderNames.CallbackHeaderPrefix, StringComparison.OrdinalIgnoreCase)))
        {
            request.Headers.Add(header.Key.Substring(AuthProxyConstants.HttpHeaderNames.CallbackHeaderPrefix.Length), header.Value.ToArray());
        }

        // Send the request through the next handler.
        return await base.SendAsync(request, cancellationToken);
    }
}