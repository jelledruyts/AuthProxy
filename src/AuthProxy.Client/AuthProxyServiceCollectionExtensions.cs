using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthProxy.Client;

public static class AuthProxyServiceCollectionExtensions
{
    public static IServiceCollection AddAuthProxy(this IServiceCollection services, IConfiguration namedConfigurationSection)
    {
        var options = namedConfigurationSection.Get<AuthProxyOptions>();
        if (options == null)
        {
            throw new ArgumentException(nameof(namedConfigurationSection), "The AuthProxy configuration section is missing or invalid.");
        }
        return services.AddAuthProxy(options);
    }

    public static IServiceCollection AddAuthProxy(this IServiceCollection services, Action<AuthProxyOptions> configureOptions)
    {
        var options = new AuthProxyOptions();
        configureOptions.Invoke(options);
        return services.AddAuthProxy(options);
    }

    public static IServiceCollection AddAuthProxy(this IServiceCollection services, AuthProxyOptions options)
    {
        // Add the options so that it can be retrieved by other services.
        services.AddSingleton<AuthProxyOptions>(options);

        // Add the HTTP context accessor service, which is needed for the HTTP message handler and API client.
        services.AddHttpContextAccessor();

        // Add the HTTP message handler which can add the authorization for the proxy's API.
        services.AddScoped<AuthProxyAuthorizationHttpMessageHandler>();

        // Add the HTTP message handler which can transform a regular HTTP request into a request towards
        // the proxy's Forward API.
        services.AddScoped<AuthProxyForwardApiHttpMessageHandler>();

        // Add a typed HTTP client for the proxy's API.
        services.AddHttpClient<AuthProxyApiService>()
            .AddHttpMessageHandler<AuthProxyAuthorizationHttpMessageHandler>();

        // Add a well-known HTTP client which has the HTTP message handler in its pipeline.
        services.AddHttpClient(AuthProxyConstants.HttpClientNames.ForwardApi)
            .AddHttpMessageHandler<AuthProxyAuthorizationHttpMessageHandler>()
            .AddHttpMessageHandler<AuthProxyForwardApiHttpMessageHandler>();

        // Add authentication based on the incoming JWT issued by the reverse proxy.
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwtBearerOptions =>
            {
                jwtBearerOptions.Authority = options.BaseUrl; // Refer back to Auth Proxy's OIDC metadata endpoint to validate incoming tokens.
                jwtBearerOptions.TokenValidationParameters.ValidIssuer = options.ValidIssuer; // The issuer of the token is defined in Auth Proxy's configuration.
                jwtBearerOptions.TokenValidationParameters.ValidAudience = options.ValidAudience; // The audience of the token is defined in Auth Proxy's configuration.
                jwtBearerOptions.TokenValidationParameters.NameClaimType = options.NameClaimType; // The name claim type depends on claim transformation configuration.
                jwtBearerOptions.TokenValidationParameters.RoleClaimType = options.RoleClaimType; // The role claim type depends on claim transformation configuration.
            });

        // In case the reverse proxy is configured to overwrite the host header, ensure the app
        // "sees" the original request URL by inspecting the headers added by the reverse proxy.
        // See https://docs.microsoft.com/aspnet/core/host-and-deploy/proxy-load-balancer.
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto;
        });

        return services;
    }
}