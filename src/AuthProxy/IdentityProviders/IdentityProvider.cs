using System.Net;
using AuthProxy.Configuration;
using Microsoft.AspNetCore.Authentication;

namespace AuthProxy.IdentityProviders;

public abstract class IdentityProvider
{
    public IdentityProviderConfig Configuration { get; }
    public string AuthenticationScheme {get;}
    public string LoginPath {get; }
    public string LoginCallbackPath {get; }
    public string PostLoginReturnUrlQueryParameterName {get; }

    protected IdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
    {
        this.Configuration = configuration;
        this.AuthenticationScheme = authenticationScheme;
        this.LoginPath = loginPath;
        this.LoginCallbackPath = loginCallbackPath;
        this.PostLoginReturnUrlQueryParameterName = postLoginReturnUrlQueryParameterName;
    }

    public abstract void AddAuthentication(AuthenticationBuilder authenticationBuilder);

    public virtual async Task RequestLogin(HttpContext httpContext)
    {
        var returnUrl = "/";
        if (httpContext.Request.Query.TryGetValue(this.PostLoginReturnUrlQueryParameterName, out var postLoginReturnUrlValue))
        {
            returnUrl = postLoginReturnUrlValue.First();
        }
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            // The user isn't logged in, redirect to the identity provider and capture the return URL.
            await httpContext.ChallengeAsync(this.AuthenticationScheme, new AuthenticationProperties { RedirectUri = returnUrl });
        }
        else
        {
            // The user is already logged in, redirect straight back to the requested URL.
            httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
            httpContext.Response.Headers.Location = returnUrl;
        }
    }
}