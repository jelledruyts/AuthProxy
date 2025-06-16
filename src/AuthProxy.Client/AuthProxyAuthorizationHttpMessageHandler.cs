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

        // Add the required authorization header for the proxy's callback API, which is injected on the incoming request.
        var authorizationHeaderName = httpContext.Request.Headers[AuthProxyConstants.HttpHeaderNames.CallbackAuthorizationHeaderName].First();
        var authorizationHeaderValue = httpContext.Request.Headers[AuthProxyConstants.HttpHeaderNames.CallbackAuthorizationHeaderValue].First();
        if (string.IsNullOrEmpty(authorizationHeaderName) || string.IsNullOrEmpty(authorizationHeaderValue))
        {
            throw new InvalidOperationException("The authorization header name or value is missing.");
        }
        request.Headers.Add(authorizationHeaderName, authorizationHeaderValue);

        // Send the request through the next handler.
        return await base.SendAsync(request, cancellationToken);
    }
}