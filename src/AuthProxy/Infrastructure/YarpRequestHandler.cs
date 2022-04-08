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
    private readonly IList<InboundPolicyConfig> inboundPolicies;

    public YarpRequestHandler(ILogger<YarpRequestHandler> logger, IHttpForwarder forwarder, AuthProxyConfig authProxyConfig)
    {
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.TokenIssuer);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.TokenIssuer.Audience);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.TokenIssuer.Issuer);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.TokenIssuer.Expiration);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.TokenIssuer.SigningSecret);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.Cookie);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Authentication.Cookie.Name);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Backend);
        ArgumentNullException.ThrowIfNull(authProxyConfig.Backend.Url);
        this.logger = logger;
        this.forwarder = forwarder;
        this.defaultTransformer = HttpTransformer.Default;
        var tokenIssuer = new TokenIssuer(authProxyConfig.Authentication.TokenIssuer.Audience, authProxyConfig.Authentication.TokenIssuer.Issuer, authProxyConfig.Authentication.TokenIssuer.Expiration.Value, authProxyConfig.Authentication.TokenIssuer.SigningSecret);
        this.customTransformer = new YarpHttpTransformer(authProxyConfig.Authentication.Cookie.Name, tokenIssuer);
        this.requestOptions = new ForwarderRequestConfig { ActivityTimeout = TimeSpan.FromSeconds(100) };
        this.httpClient = new HttpMessageInvoker(new SocketsHttpHandler()
        {
            UseProxy = false,
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.None,
            UseCookies = false,
            ActivityHeadersPropagator = new ReverseProxyPropagator(DistributedContextPropagator.Current)
        });
        this.backendAppUrl = authProxyConfig.Backend.Url;
        this.inboundPolicies = authProxyConfig.Policies?.Inbound ?? Array.Empty<InboundPolicyConfig>();
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
            // Check if there is a matching inbound policy.
            var shouldForwardRequest = true;
            var inboundPolicy = GetMatchingInboundPolicy(httpContext.Request);
            if (inboundPolicy != null)
            {
                // An inbound policy applies to the request, check the required action.
                if (inboundPolicy.Action == PolicyAction.Allow)
                {
                    shouldForwardRequest = true;
                }
                else if (inboundPolicy.Action == PolicyAction.Authenticate)
                {
                    // Authentication is required, check if the user is already authenticated.
                    if (httpContext.User.Identity?.IsAuthenticated == true)
                    {
                        // The user is already authenticated, check if the policy requires specific IdPs.
                        if (inboundPolicy.IdentityProviders != null && inboundPolicy.IdentityProviders.Any())
                        {
                            var metadataIdentity = httpContext.User.GetIdentity(Constants.AuthenticationTypes.Metadata);
                            var idpNameClaim = metadataIdentity?.FindFirst(Constants.ClaimTypes.Metadata.IdentityProviderName);
                            if (idpNameClaim == null || !inboundPolicy.IdentityProviders.Contains(idpNameClaim.Value, StringComparer.OrdinalIgnoreCase))
                            {
                                // The user was authenticated but NOT with one of the allowed IdPs specified on the policy.
                                // TODO: Allow configuration to decide what to do when authenticated but not with a matching IdP:
                                // either force authentication to an explicitly specified IdP or deny the request.
                                // TODO: Make status code configurable.
                                shouldForwardRequest = false;
                                httpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                                await httpContext.Response.CompleteAsync();
                            }
                        }
                    }
                    else
                    {
                        // The user is not yet authenticated, trigger an authentication.
                        // If any IdPs were specified on the policy, use the first one to authenticate the user; otherwise use the default scheme.
                        shouldForwardRequest = false;
                        var scheme = inboundPolicy.IdentityProviders?.FirstOrDefault() ?? Defaults.AuthenticationScheme;
                        await httpContext.ChallengeAsync(scheme);
                    }
                }
                else if (inboundPolicy.Action == PolicyAction.Deny)
                {
                    // The request is explicitly denied.
                    // TODO: Make status code configurable.
                    shouldForwardRequest = false;
                    httpContext.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                    await httpContext.Response.CompleteAsync();
                }

            }

            if (shouldForwardRequest)
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

    private InboundPolicyConfig? GetMatchingInboundPolicy(HttpRequest request)
    {
        foreach (var inboundPolicy in this.inboundPolicies)
        {
            // TODO: Support more than a simple "starts with" match on the path pattern.
            if (inboundPolicy.PathPatterns != null && inboundPolicy.PathPatterns.Any(p => request.Path.StartsWithSegments(new PathString(p), StringComparison.InvariantCultureIgnoreCase)))
            {
                // Stop processing more inbound policies when a match was found.
                return inboundPolicy;
            }
        }
        return null;
    }
}