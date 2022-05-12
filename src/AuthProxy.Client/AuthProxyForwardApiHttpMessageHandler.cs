using AuthProxy.Models;
using Microsoft.AspNetCore.Http;

namespace AuthProxy.Client;

public class AuthProxyForwardApiHttpMessageHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor httpContextAccessor;
    private readonly AuthProxyOptions options;
    private readonly Uri authProxyBaseUrl;

    public AuthProxyForwardApiHttpMessageHandler(IHttpContextAccessor httpContextAccessor, AuthProxyOptions options)
    {
        ArgumentNullException.ThrowIfNull(options.BaseUrl);
        this.httpContextAccessor = httpContextAccessor;
        this.options = options;
        this.authProxyBaseUrl = new Uri(this.options.BaseUrl);
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        // Get the ambient HTTP context.
        ArgumentNullException.ThrowIfNull(this.httpContextAccessor.HttpContext);
        var httpContext = this.httpContextAccessor.HttpContext;

        // Change the HTTP request to move the actual requested URL into a special HTTP
        // header that the proxy knows to look for.
        request.Headers.Add(AuthProxyConstants.HttpHeaderNames.Destination, request.RequestUri?.ToString());

        // Retrieve the path to the Forward API from the headers to avoid hard-coding it.
        var forwardApiPath = httpContext.Request.Headers[AuthProxyConstants.HttpHeaderNames.CallbackForwardEndpoint].First();

        // Overwrite the request URL with the absolute URL of the proxy's Forward API.
        request.RequestUri = new Uri(this.authProxyBaseUrl, forwardApiPath);

        // Send the request through the proxy.
        var response = await base.SendAsync(request, cancellationToken);

        // If configured, check if a redirect is required.
        if (this.options.AutoRedirectWhenRequired)
        {
            var tokenResponse = response.ToTokenResponse();
            if (tokenResponse != null && tokenResponse.Status == TokenResponseStatus.RedirectRequired)
            {
                // The token request could not be completed, user interaction is required.
                // Signal to the exception handler that a redirect is required.
                throw new AuthProxyTokenAcquisitionException(tokenResponse);
            }
        }
        return response;
    }
}