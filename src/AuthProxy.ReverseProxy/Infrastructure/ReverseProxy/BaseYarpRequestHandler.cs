using System.Diagnostics;
using System.Net;
using Microsoft.AspNetCore.Http.Extensions;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.ReverseProxy.Infrastructure.ReverseProxy;

public abstract class BaseYarpRequestHandler
{
    protected ILogger Logger { get; }
    private readonly IHttpForwarder forwarder;
    private readonly HttpTransformer transformer;
    private readonly ForwarderRequestConfig requestOptions;
    private readonly HttpMessageInvoker httpClient;

    public BaseYarpRequestHandler(ILogger logger, IHttpForwarder forwarder, HttpTransformer transformer)
    {
        this.Logger = logger;
        this.forwarder = forwarder;
        this.transformer = transformer;
        this.requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };
        this.httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
        });
    }

    public async Task HandleRequest(HttpContext httpContext)
    {
        var shouldForward = await ShouldForwardRequestAsync(httpContext);
        if (shouldForward)
        {
            // Forward the incoming request to the external service.
            var destinationPrefix = GetDestinationPrefix(httpContext) ?? string.Empty;
            var error = await this.forwarder.SendAsync(httpContext, destinationPrefix, this.httpClient, this.requestOptions, this.transformer);
            if (error != ForwarderError.None)
            {
                var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                var exception = errorFeature?.Exception;
                this.Logger.LogError(exception, "Could not forward request to forward destination");
            }
        }
    }

    protected abstract Task<bool> ShouldForwardRequestAsync(HttpContext httpContext);

    protected virtual string? GetDestinationPrefix(HttpContext httpContext)
    {
        return httpContext.Request.GetEncodedUrl();
    }

    protected async Task<bool> ForbiddenAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
        await httpContext.Response.CompleteAsync();
        return false;
    }
}