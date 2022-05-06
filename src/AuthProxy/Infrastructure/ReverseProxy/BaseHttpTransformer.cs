using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure.ReverseProxy;

public abstract class BaseHttpTransformer : HttpTransformer
{
    /// <summary>
    /// A callback that is invoked prior to sending the proxied request. All HttpRequestMessage fields are
    /// initialized except RequestUri, which will be initialized after the callback if no value is provided.
    /// See <see cref="RequestUtilities.MakeDestinationAddress(string, PathString, QueryString)"/> for constructing a custom request Uri.
    /// The string parameter represents the destination URI prefix that should be used when constructing the RequestUri.
    /// The headers are copied by the base implementation, excluding some protocol headers like HTTP/2 pseudo headers (":authority").
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyRequest">The outgoing proxy request.</param>
    /// <param name="destinationPrefix">The uri prefix for the selected destination server which can be used to create the RequestUri.</param>
    public override async ValueTask TransformRequestAsync(HttpContext httpContext, HttpRequestMessage proxyRequest, string destinationPrefix)
    {
        // Perform default behavior.
        await HttpTransformer.Default.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix);
    }

    /// <summary>
    /// A callback that is invoked when the proxied response is received. The status code and reason phrase will be copied
    /// to the HttpContext.Response before the callback is invoked, but may still be modified there. The headers will be
    /// copied to HttpContext.Response.Headers by the base implementation, excludes certain protocol headers like
    /// `Transfer-Encoding: chunked`.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination. This can be null if the destination did not respond.</param>
    /// <returns>A bool indicating if the response should be proxied to the client or not. A derived implementation 
    /// that returns false may send an alternate response inline or return control to the caller for it to retry, respond, 
    /// etc.</returns>
    public override ValueTask<bool> TransformResponseAsync(HttpContext httpContext, HttpResponseMessage? proxyResponse)
    {
        // Perform default behavior.
        return HttpTransformer.Default.TransformResponseAsync(httpContext, proxyResponse);
    }

    /// <summary>
    /// A callback that is invoked after the response body to modify trailers, if supported. The trailers will be
    /// copied to the HttpContext.Response by the base implementation.
    /// </summary>
    /// <param name="httpContext">The incoming request.</param>
    /// <param name="proxyResponse">The response from the destination.</param>
    public override ValueTask TransformResponseTrailersAsync(HttpContext httpContext, HttpResponseMessage proxyResponse)
    {
        // Perform default behavior.
        return HttpTransformer.Default.TransformResponseTrailersAsync(httpContext, proxyResponse);
    }
}