using System.Net;
using AuthProxy.Configuration;
using AuthProxy.Infrastructure;
using AuthProxy.Models;
using Duende.AccessTokenManagement;
using Duende.AccessTokenManagement.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthProxy.IdentityProviders;

public class OpenIdConnectIdentityProvider : IdentityProvider
{
    public const string ClaimTypeBearerToken = "bearer_token";
    private OpenIdConnectOptions? openIdConnectOptions;
    private OpenIdConnectClientConfiguration? oidcConfiguration;
    private ClientCredentialsClient? clientCredentialsClient;

    public OpenIdConnectIdentityProvider(IdentityProviderConfig config, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(config, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
    }

    public override void AddAuthentication(AuthenticationBuilder authenticationBuilder)
    {
        authenticationBuilder.Services.AddDistributedMemoryCache();
        authenticationBuilder.Services.AddClientCredentialsTokenManagement().AddClient(this.AuthenticationScheme, options =>
        {
            // Keep the client credentials client options for later use, as it needs a token
            // endpoint property but this has to be retrieved from OpenID Connect metadata
            // dynamically. This could already have been done before this options object is
            // configured, in which case we fill it in here; if not it will be filled in
            // later in the GetTokenAsync method.
            this.clientCredentialsClient = options;
            options.TokenEndpoint = this.oidcConfiguration?.TokenEndpoint;
            options.ClientId = this.Configuration.ClientId;
            options.ClientSecret = this.Configuration.ClientSecret;
            options.Scope = this.Configuration.TokenRequestScopes.GetScopeString();
        });
        authenticationBuilder.Services.AddOpenIdConnectAccessTokenManagement();
        authenticationBuilder.AddOpenIdConnect(this.AuthenticationScheme, options =>
        {
            this.openIdConnectOptions = options;

            // Set main options.
            options.ClaimActions.Clear(); // Don't change any incoming claims, let the claims transformer do that.
            options.Authority = this.Configuration.Authority;
            options.ClientId = this.Configuration.ClientId;
            options.ClientSecret = this.Configuration.ClientSecret;
            options.CallbackPath = this.LoginCallbackPath; // Note that the callback path must be unique per identity provider.
            options.NonceCookie.Name = Constants.Defaults.CookiePrefix + "OpenIdConnect.Nonce";
            options.CorrelationCookie.Name = Constants.Defaults.CookiePrefix + "OpenIdConnect.Correlation";
            options.UsePkce = this.Configuration.UsePkce;
            options.GetClaimsFromUserInfoEndpoint = this.Configuration.GetClaimsFromUserInfoEndpoint;
            options.SaveTokens = true;

            // By default, request "code id_token" to retrieve an authorization code along with the id_token.
            // In case no access token is ever needed, this can be overridden in configuration to simply use "id_token"
            // (in which case a client secret isn't even needed).
            options.ResponseType = this.Configuration.ResponseType;

            // Default scopes are added automatically; add statically configured scopes for sign in.
            AddScopes(options.Scope, this.Configuration.SignInScopes);

            // Set token validation parameters.
            options.TokenValidationParameters.ValidAudiences = this.Configuration.AllowedAudiences; // TODO: Warn if there are no valid audiences configured.
            options.TokenValidationParameters.ValidIssuers = this.Configuration.AllowedIssuers;

            // Handle events.
            options.Events = GetEvents();

            // Allow customization of the options.
            OnOptionsConfigured(options);
        });

        // Add a second authentication provider for Web APIs using the JWT bearer scheme.
        var jwtBearerScheme = this.AuthenticationScheme + "-JwtBearer";
        this.AuthenticationSchemes.Add(jwtBearerScheme);
        authenticationBuilder.AddJwtBearer(jwtBearerScheme, options =>
        {
            // Set main options.
            options.Authority = this.Configuration.Authority;

            // Set token validation parameters.
            options.TokenValidationParameters.ValidAudiences = this.Configuration.AllowedAudiences; // TODO: Warn if there are no valid audiences configured.
            options.TokenValidationParameters.ValidIssuers = this.Configuration.AllowedIssuers;

            // Handle events.
            options.Events = GetJwtBearerEvents();

            // Allow customization of the options.
            OnOptionsConfigured(options);
        });
    }

    protected virtual OpenIdConnectEvents GetEvents()
    {
        var claimsTransformer = GetClaimsTransformer();
        return new OpenIdConnectIdentityProviderEvents<OpenIdConnectIdentityProvider>(this, claimsTransformer);
    }

    protected virtual void OnOptionsConfigured(OpenIdConnectOptions options)
    {
        return;
    }

    protected virtual JwtBearerEvents GetJwtBearerEvents()
    {
        var claimsTransformer = GetClaimsTransformer();
        return new OpenIdConnectIdentityProviderJwtBearerEvents<OpenIdConnectIdentityProvider>(this, claimsTransformer);
    }

    protected virtual void OnOptionsConfigured(JwtBearerOptions options)
    {
        return;
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

    public override async Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request)
    {
        if (request.Actor == null || request.Actor == Actor.User)
        {
            var tokenManagementService = httpContext.RequestServices.GetRequiredService<IUserTokenManagementService>();
            var parameters = new UserTokenRequestParameters
            {
                ChallengeScheme = this.AuthenticationScheme,
                Scope = request.Scopes.GetScopeString()
            };
            // TODO: If the "current/original" access token wasn't initially requested for the specified
            // scopes, the token management service will return the current access token without checking
            // the scopes requested here. This means the returned access token might not contain the requested scopes,
            // which is a problem if the backend app requires those scopes to be present in the access token.
            // To avoid mismatching scopes, make sure to request the right scopes upfront as part of the authentication
            // challenge for now.
            // https://github.com/DuendeSoftware/foss/blob/368f47d47cbe4ada94a82fe1e2bbdc97eb7c747b/access-token-management/src/AccessTokenManagement.OpenIdConnect/UserAccessTokenManagementService.cs#L49
            var token = await tokenManagementService.GetAccessTokenAsync(httpContext.User, parameters);
            if (string.IsNullOrWhiteSpace(token.AccessToken))
            {
                return TokenResponse.Failed(token.Error);
            }
            else
            {
                return TokenResponse.Succeeded(token.AccessToken);
            }
        }
        else if (request.Actor == Actor.App)
        {
            var tokenManagementService = httpContext.RequestServices.GetRequiredService<IClientCredentialsTokenManagementService>();
            var parameters = new TokenRequestParameters
            {
                Scope = request.Scopes.GetScopeString()
            };
            if (string.IsNullOrEmpty(this.clientCredentialsClient?.TokenEndpoint))
            {
                // Infer the token endpoint from the OpenID Connect metadata if not set explicitly.
                var oidcConfigurationManager = httpContext.RequestServices.GetRequiredService<IOpenIdConnectConfigurationService>();
                this.oidcConfiguration = await oidcConfigurationManager.GetOpenIdConnectConfigurationAsync(this.AuthenticationScheme);
                if (this.clientCredentialsClient != null)
                {
                    this.clientCredentialsClient.TokenEndpoint = this.oidcConfiguration.TokenEndpoint;
                }
            }
            var token = await tokenManagementService.GetAccessTokenAsync(this.AuthenticationScheme, parameters);
            if (string.IsNullOrWhiteSpace(token.AccessToken))
            {
                return TokenResponse.Failed(token.Error);
            }
            else
            {
                return TokenResponse.Succeeded(token.AccessToken);
            }
        }
        else if (request.Actor == Actor.AzureManagedIdentity)
        {
            return TokenResponse.Failed($"Acquiring tokens for an Azure Managed Identity is not supported with the \"{this.Configuration.Type}\" identity provider.");
        }
        return await GetTokenResponseForRedirectAsync(httpContext, request);
    }

    protected async virtual Task<TokenResponse> GetTokenResponseForRedirectAsync(HttpContext httpContext, TokenRequest request)
    {
        var properties = new AuthenticationProperties();
        properties.RedirectUri = request.ReturnUrl;

        // Default scopes are added automatically; add statically configured scopes for token requests
        // and dynamically requested scopes from the token request.
        var scopesToRequest = new List<string>();
        AddScopes(scopesToRequest, this.Configuration.TokenRequestScopes);
        AddScopes(scopesToRequest, request.Scopes);
        properties.SetParameter(OpenIdConnectParameterNames.Scope, scopesToRequest);

        // Remember original response properties.
        var oldStatusCode = httpContext.Response.StatusCode;
        var oldRedirectUrl = httpContext.Response.Headers.Location;
        var oldRedirectCookies = httpContext.Response.Headers.SetCookie.ToArray();
        try
        {
            // TODO: This sets the current response to redirect so we can extract the redirect URL;
            // later on the response status and body will be replaced again with the result of the current API call.
            // There might be a cleaner way to get the redirect URL without impacting the actual current HTTP context,
            // although the authentication handler does seem to only work by triggering the redirect without a
            // clean way to build the redirect URL separately, see
            // https://github.com/dotnet/aspnetcore/blob/main/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectHandler.cs#L364.
            await httpContext.ChallengeAsync(this.AuthenticationScheme, properties);
            var redirectUrl = httpContext.Response.Headers.Location.ToString();
            if (this.openIdConnectOptions != null && !this.openIdConnectOptions.ResponseType.Contains(OpenIdConnectResponseType.Code))
            {
                // Because we use ChallengeAsync to get a redirect URL and that uses the statically configured
                // ResponseType defined in the OpenIdConnectOptions, we cannot dynamically override it
                // to use an authorization code flow when needed: the "code" response type should already have
                // been included in the OpenIdConnectOptions even if no access token was initially required.
                // As a workaround, we modify the generated redirect URL directly to change the response type
                // in case the initial sign-in did not request an authorization code flow.
                var responseTypeWithoutCode = OpenIdConnectParameterNames.ResponseType + "=" + WebUtility.UrlEncode(this.openIdConnectOptions.ResponseType);
                var responseTypeWithCode = OpenIdConnectParameterNames.ResponseType + "=" + WebUtility.UrlEncode($"{OpenIdConnectResponseType.Code} {this.openIdConnectOptions.ResponseType}");
                redirectUrl = redirectUrl.Replace(responseTypeWithoutCode, responseTypeWithCode);
            }
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

    protected void AddScopes(ICollection<string> target, ICollection<string>? scopes)
    {
        // The "openid" and "profile" scopes are added implicitly by middleware, add them explicitly here for use with MSAL.
        foreach (var scope in OpenIdConnectScope.OpenIdProfile.GetScopeValues())
        {
            AddScope(target, scope);
        }

        // Add the statically defined default scopes.
        foreach (var scope in this.Configuration.DefaultScopes)
        {
            AddScope(target, scope);
        }

        // Add the dynamically requested scopes.
        if (scopes != null)
        {
            foreach (var scope in scopes)
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