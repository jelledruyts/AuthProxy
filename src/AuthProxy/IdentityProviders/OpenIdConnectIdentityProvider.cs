using AuthProxy.Configuration;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProvider : IdentityProvider
{
    public OpenIdConnectIdentityProvider(IdentityProviderConfig config, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(config, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
    }

    public override void AddAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        authenticationBuilder.AddOpenIdConnect(this.AuthenticationScheme, options =>
        {
            // Set main options.
            options.ClaimActions.Clear(); // Don't change any incoming claims, let the claims transformer do that.
            options.Authority = this.Configuration.Authority;
            // TODO-M: Because we use ChallengeAsync to get a redirect URL (see GetTokenResponseForRedirectAsync)
            // and that uses the statically configured ResponseType defined here, we cannot dynamically
            // override it to use an auth code flow only when needed: the "code" response type must already
            // be included here even if no access token is initially required. This restriction may be removed
            // when using a different mechanism to build the redirect URL instead of ChallengeAsync.
            // In that case, we can check if the configured scopes are *only* standard OIDC scopes in which case we
            // only request "id_token"; if there's at least one non-standard OIDC scope, then we request "code id_token".
            options.ResponseType = OpenIdConnectResponseType.CodeIdToken; // TODO-L: In case no access token is ever needed, can simplify to use "id_token" and avoid client secret.
            var requestRefreshToken = true; // TODO-L: Only if needed (non-default OIDC scope)
            AddScopes(options.Scope, requestRefreshToken, true, null);
            options.ClientId = this.Configuration.ClientId;
            options.ClientSecret = this.Configuration.ClientSecret;
            options.CallbackPath = this.LoginCallbackPath; // Note that the callback path must be unique per identity provider.

            // Set token validation parameters.
            options.TokenValidationParameters.ValidAudiences = this.Configuration.AllowedAudiences; // TODO-L: Warn if there are no valid audiences configured.

            // Handle events.
            options.Events = GetEvents();
        });
    }

    protected virtual OpenIdConnectEvents GetEvents()
    {
        var claimsTransformer = GetClaimsTransformer();
        return new OpenIdConnectIdentityProviderEvents<OpenIdConnectIdentityProvider>(this, claimsTransformer);
    }

    protected override IList<string> GetDefaultClaimTransformations()
    {
        var claimTransformations = base.GetDefaultClaimTransformations();
        // claimTransformations.Add("iss = "); // Don't map the issuer, the backend app can be reached through multiple IdPs and it shouldn't care which one was used.
        // claimTransformations.Add("azp = "); // Don't map the authorized party, the backend app can be reached through multiple clients and it shouldn't care which one was used.
        // claimTransformations.Add("aud = "); // Don't map the audience, the backend app can be reached through multiple IdPs/audiences and it shouldn't care which one was used.
        claimTransformations.Add("sub = sub + '@' + iss"); // Don't map the subject directly as it's unique within the IdP only, concatenate it with the issuer claim to avoid conflicts between different users with the same subject across IdPs.
        claimTransformations.Add("acr"); // Map the Authentication Context Class Reference to itself (shorthand syntax).
        claimTransformations.Add("amr"); // Map the Authentication Methods References to itself (shorthand syntax).
        return claimTransformations;
    }

    public override Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request)
    {
        // TODO-H: Provide a basic implementation (not using MSAL).
        throw new NotImplementedException();
    }

    protected async virtual Task<TokenResponse> GetTokenResponseForRedirectAsync(HttpContext httpContext, TokenRequest request)
    {
        var properties = new AuthenticationProperties();
        properties.RedirectUri = request.ReturnUrl;
        var scopesToRequest = new List<string>();
        AddScopes(scopesToRequest, true, false, request.Scopes);
        properties.SetParameter(OpenIdConnectParameterNames.Scope, scopesToRequest);

        // Remember original response properties.
        var oldStatusCode = httpContext.Response.StatusCode;
        var oldRedirectUrl = httpContext.Response.Headers.Location;
        var oldRedirectCookies = httpContext.Response.Headers.SetCookie.ToArray();
        try
        {
            // TODO-L: This sets the current response to redirect so we can extract the redirect URL; later on the
            // response status and body will be replaced again with the result of the current API call but there
            // might be a cleaner way to get the redirect URL without impacting the actual current http context
            // (although the authentication handler does seem to only work by triggering the redirect without a
            // clean way to build the redirect URL separately, see
            // https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectHandler.cs#L364).
            await httpContext.ChallengeAsync(this.AuthenticationScheme, properties);
            var redirectUrl = httpContext.Response.Headers.Location;
            var redirectCookies = httpContext.Response.Headers.SetCookie;
            return new TokenResponse { Status = TokenResponseStatus.RedirectRequired, RedirectUrl = redirectUrl, RedirectCookies = redirectCookies };
        }
        finally
        {
            // Reset the original response properties.
            httpContext.Response.StatusCode = oldStatusCode;
            httpContext.Response.Headers.Location = oldRedirectUrl;
            httpContext.Response.Headers.SetCookie = oldRedirectCookies;
        }
    }

    protected void AddScopes(ICollection<string> target, bool requestRefreshToken, bool includeConfiguredScopes, ICollection<string>? additionalScopes)
    {
        // The "openid" scope is added implicitly by middleware, add it explicitly here for use with MSAL.
        AddScope(target, OpenIdConnectScope.OpenId);

        // Only if needed and allowed, request a refresh token as part of the flow.
        if (requestRefreshToken && this.Configuration.AllowRefreshTokens)
        {
            AddScope(target, OpenIdConnectScope.OfflineAccess);
        }

        // Add the statically defined scopes if needed.
        if (includeConfiguredScopes && this.Configuration.Scopes != null)
        {
            foreach (var scope in this.Configuration.Scopes)
            {
                AddScope(target, scope);
            }
        }

        // Add the dynamically requested scopes.
        if (additionalScopes != null)
        {
            foreach (var scope in additionalScopes)
            {
                AddScope(target, scope);
            }
        }
    }

    private void AddScope(ICollection<string> scopesToRequest, string scope)
    {
        if (!scopesToRequest.Contains(scope))
        {
            scopesToRequest.Add(scope);
        }
    }
}