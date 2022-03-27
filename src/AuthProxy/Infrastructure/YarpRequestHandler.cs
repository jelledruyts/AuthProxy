using System.Diagnostics;
using System.Net;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;
using Yarp.ReverseProxy.Forwarder;

namespace AuthProxy.Infrastructure;

public class YarpRequestHandler
{
    private readonly ILogger<YarpRequestHandler> logger;
    private readonly IHttpForwarder forwarder;
    private readonly HttpTransformer defaultTransformer;
    private readonly HttpTransformer customTransformer;
    private readonly ForwarderRequestConfig requestOptions;
    private readonly HttpMessageInvoker httpClient;
    private readonly string backendAppUrl;

    public YarpRequestHandler(ILogger<YarpRequestHandler> logger, IHttpForwarder forwarder, AuthProxyConfig authProxyConfig)
    {
        this.logger = logger;
        this.forwarder = forwarder;
        this.defaultTransformer = HttpTransformer.Default;
        var tokenIssuer = new TokenIssuer(authProxyConfig.Authentication!.TokenIssuer!.Audience!, authProxyConfig.Authentication!.TokenIssuer!.Issuer!, authProxyConfig.Authentication!.TokenIssuer!.Expiration!.Value, authProxyConfig.Authentication!.TokenIssuer!.SigningSecret!);
        this.customTransformer = new YarpHttpTransformer(authProxyConfig.Authentication!.Cookie!.Name!, tokenIssuer);
        this.requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };
        this.httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
        });
        this.backendAppUrl = authProxyConfig!.Backend!.Url!;
    }

    public async Task HandleRequest(HttpContext httpContext)
    {
        var isForwardProxyRequest = httpContext.Request.Host.Host != "localhost"; // TODO: Should check on all "allowed" host names that the backend app expects.
        if (isForwardProxyRequest)
        {
            // EXPERIMENTAL!
            // This is a forward proxy request coming from the backend app (which has the proxy set as its HTTP proxy)
            // to reach an external service; forward the incoming request to the original destination.
            // TODO: YARP doesn't support CONNECT requests to tunnel the HTTPS traffic through to the backend,
            // so have to find another way to transparently attach tokens to outbound calls (if possible).
            var uriBuilder = new UriBuilder(httpContext.Request.Scheme, httpContext.Request.Host.Host, httpContext.Request.Host.Port.GetValueOrDefault(httpContext.Request.IsHttps ? 443 : 80));
            var destinationPrefix = uriBuilder.ToString();
            var error = await this.forwarder.SendAsync(httpContext, destinationPrefix, this.httpClient, this.requestOptions, this.defaultTransformer);
            if (error != ForwarderError.None)
            {
                var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                var exception = errorFeature?.Exception;
                this.logger.LogError(exception, "Could not forward request to external service");
            }
        }
        else
        {
            // This is a reverse proxy request for the backend app.
            var shouldPreAuthenticate = false; // TODO: Check inbound path patterns.
            if (shouldPreAuthenticate && httpContext.User.Identity?.IsAuthenticated != true)
            {
                var scheme = Defaults.AuthenticationScheme; // TODO: Scheme (IdP) depends on requested path.
                await httpContext.ChallengeAsync(scheme);
            }
            else
            {
                // Forward the incoming request to the backend app.
                var error = await this.forwarder.SendAsync(httpContext, this.backendAppUrl, this.httpClient, this.requestOptions, this.customTransformer);
                if (error != ForwarderError.None)
                {
                    var errorFeature = httpContext.Features.Get<IForwarderErrorFeature>();
                    var exception = errorFeature?.Exception;
                    this.logger.LogError(exception, "Could not forward request to backend app");
                }
            }
        }
    }
}