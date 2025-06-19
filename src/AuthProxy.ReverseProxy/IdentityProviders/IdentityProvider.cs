using System.Net;
using AuthProxy.Models;
using AuthProxy.ReverseProxy.Configuration;
using AuthProxy.ReverseProxy.Infrastructure;
using Microsoft.AspNetCore.Authentication;

namespace AuthProxy.ReverseProxy.IdentityProviders;

public abstract class IdentityProvider
{
    public IdentityProviderConfig Configuration { get; }
    public string AuthenticationScheme => this.AuthenticationSchemes.First();
    public List<string> AuthenticationSchemes { get; } = new List<string>();
    public string LoginPath { get; }
    public string LoginCallbackPath { get; }
    public string PostLoginReturnUrlQueryParameterName { get; }

    protected IdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
    {
        this.Configuration = configuration;
        this.AuthenticationSchemes.Add(authenticationScheme);
        this.LoginPath = loginPath;
        this.LoginCallbackPath = loginCallbackPath;
        this.PostLoginReturnUrlQueryParameterName = postLoginReturnUrlQueryParameterName;
    }

    public abstract void AddAuthentication(AuthenticationBuilder authenticationBuilder);

    public virtual async Task RequestLoginAsync(HttpContext httpContext)
    {
        var returnUrl = "/";
        if (httpContext.Request.Query.TryGetValue(this.PostLoginReturnUrlQueryParameterName, out var postLoginReturnUrlValue))
        {
            returnUrl = postLoginReturnUrlValue.First();
        }
        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            // The user isn't logged in, redirect to the identity provider and capture the return URL.
            await ChallengeAsync(httpContext, returnUrl);
        }
        else
        {
            // The user is already logged in, redirect straight back to the requested URL.
            httpContext.Response.StatusCode = (int)HttpStatusCode.Found;
            httpContext.Response.Headers.Location = returnUrl;
        }
    }

    public virtual async Task<bool> AttemptAuthenticateAsync(HttpContext httpContext)
    {
        foreach (var scheme in this.AuthenticationSchemes)
        {
            var result = await httpContext.AuthenticateAsync(scheme);
            if (result.Succeeded)
            {
                httpContext.User = result.Principal;
                return true;
            }
        }
        return false;
    }

    public async Task ChallengeAsync(HttpContext httpContext, string? returnUrl = null)
    {
        await httpContext.ChallengeAsync(this.AuthenticationScheme, new AuthenticationProperties { RedirectUri = returnUrl });
    }

    protected virtual IList<string> GetDefaultClaimTransformations()
    {
        return new List<string>();
    }

    protected virtual ClaimsTransformer GetClaimsTransformer()
    {
        var claimTransformations = GetDefaultClaimTransformations();
        if (this.Configuration.ClaimTransformations != null)
        {
            claimTransformations = claimTransformations.Concat(this.Configuration.ClaimTransformations).ToList();
        }
        return new ClaimsTransformer(this, claimTransformations);
    }

    public abstract Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request);
}