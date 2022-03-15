namespace AuthProxy.Configuration;

internal static class YarpConfig
{
    public static void AddYarp(this WebApplicationBuilder builder, AuthProxyConfig config)
    {
        ArgumentNullException.ThrowIfNull(config.AppUrl);

        // Note that "Direct Forwarding" (https://microsoft.github.io/reverse-proxy/articles/direct-forwarding.html)
        // would be more lightweight but isn't an option here as it doesn't support customizing the response body.
        // TODO: Are changes to the request/response BODY actually needed? Aren't headers enough?
        
        // Add core YARP configuration in code rather than from the regular config file
        // as it's an implementation detail and all configuration should come from the
        // central AuthProxy configuration instance.
        // Alternatively to using a key/value dictionary, could also use code-based config
        // (see https://microsoft.github.io/reverse-proxy/articles/config-providers.html#example).
        const string appRouteId = "route-app";
        const string appClusterId = "cluster-app";
        const string appDestinationId = "destination-app";
        var configurationData = new Dictionary<string, string>
        {
            { $"ReverseProxy:Routes:{appRouteId}:ClusterId", appClusterId},
            { $"ReverseProxy:Routes:{appRouteId}:Match:Path", "{**catch-all}"},
            { $"ReverseProxy:Clusters:{appClusterId}:Destinations:{appDestinationId}:Address", config.AppUrl},
        };
        builder.Configuration.AddInMemoryCollection(configurationData);
        builder.Services.AddReverseProxy()
            .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
    }
}