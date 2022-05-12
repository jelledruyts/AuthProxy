namespace AuthProxy.Client;

public static class HttpClientFactoryExtensions
{
    public static HttpClient CreateForwardApiHttpClient(this IHttpClientFactory httpClientFactory)
    {
        return httpClientFactory.CreateForwardApiHttpClient(null);
    }

    public static HttpClient CreateForwardApiHttpClient(this IHttpClientFactory httpClientFactory, string? returnUrl)
    {
        var httpClient = httpClientFactory.CreateClient(AuthProxyConstants.HttpClientNames.ForwardApi);
        if (returnUrl != null)
        {
            httpClient.DefaultRequestHeaders.Add(AuthProxyConstants.HttpHeaderNames.ReturnUrl, returnUrl);
        }
        return httpClient;
    }
}