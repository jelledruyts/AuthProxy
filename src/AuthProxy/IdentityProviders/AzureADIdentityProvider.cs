using System.Security.Claims;
using AuthProxy.Configuration;
using AuthProxy.Models;
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Validators;

namespace AuthProxy.IdentityProviders;

// TODO: The "login_hint" claim (if present) of the current principal's "original" (federated) identity
// can be used as the "logout_hint" when a logout is requested towards the IdP.
// See https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request.

public class AzureADIdentityProvider : OpenIdConnectIdentityProvider
{
    public const string ClaimTypeHomeAccountId = "msal_accountid";
    private const string MsalUiRequiredExceptionErrorCodeRequestedScopeMissing = "requested_scope_missing"; // A custom error code to signal that a requested scope was not granted (likely because it was not previously consented to).
    private readonly string tenantId;
    private readonly AadIssuerValidator issuerValidator;

    public AzureADIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
        ArgumentNullException.ThrowIfNull(configuration.Authority);
        this.tenantId = GetTenantId(configuration.Authority);
        this.issuerValidator = AadIssuerValidator.GetAadIssuerValidator(configuration.Authority);
    }

    protected virtual string GetTenantId(string authority)
    {
        // Ensure that the configured Azure AD authority is using v2.0.
        if (!authority.Contains("/v2.0", StringComparison.InvariantCultureIgnoreCase))
        {
            throw new ArgumentException($"The Azure AD identity provider with Authority URL \"{authority}\" doesn't use the required v2.0 endpoint (for example, \"https://login.microsoftonline.com/contoso.com/v2.0\").");
        }
        // Take the first path string before the "/", for example for
        // "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
        // the absolute path is "contoso.onmicrosoft.com/v2.0" and we
        // extract just the first part before the "/".
        return new Uri(authority).AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)[0];
    }

    protected override OpenIdConnectEvents GetEvents()
    {
        var claimsTransformer = GetClaimsTransformer();
        return new AzureADIdentityProviderEvents(this, claimsTransformer);
    }

    protected override void OnOptionsConfigured(OpenIdConnectOptions options)
    {
        // Use the Azure AD-specific issuer validator which knows how to deal with multi-tenant Azure AD and Azure AD B2C.
        // Take special care with explicitly configured issuers that should be allowed, however.
        // When the issuer is validated, it is checked against the statically configured allowed issuers, but
        // also against the issuer which is retrieved from the OIDC metadata, and the Azure AD validator is
        // explicitly aware of the "https://login.microsoftonline.com/{tenantid}/v2.0" issuer that is found in the OIDC
        // metadata document of multi-tenant endpoints so that it "just works". However, this also means that
        // the explicitly configured list is effectively ignored, because ANY issuer (tenant) is valid according to this
        // "https://login.microsoftonline.com/{tenantid}/v2.0" issuer. For that reason, when there is an explicit
        // configuration of allowed issuers, we don't use the Azure AD-specific issuer validator but we rely
        // on the built-in validator which checks against the list and nothing more.
        // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Validators/AadIssuerValidator/AadIssuerValidator.cs
        // and https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/Validators.cs.
        if (this.Configuration.AllowedIssuers == null || !this.Configuration.AllowedIssuers.Any())
        {
            options.TokenValidationParameters.IssuerValidator = this.issuerValidator.Validate;
        }
    }

    protected override void OnOptionsConfigured(JwtBearerOptions options)
    {
        // See comments above.
        if (this.Configuration.AllowedIssuers == null || !this.Configuration.AllowedIssuers.Any())
        {
            options.TokenValidationParameters.IssuerValidator = this.issuerValidator.Validate;
        }
    }

    protected override IList<string> GetDefaultClaimTransformations()
    {
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        var claimTransformations = base.GetDefaultClaimTransformations();
        claimTransformations.Add($"{AuthProxyConstants.Defaults.NameClaimType}=preferred_username");
        claimTransformations.Add(AuthProxyConstants.Defaults.RoleClaimType);
        claimTransformations.Add("email");
        return claimTransformations;
    }

    public async override Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request)
    {
        try
        {
            var confidentialClientApplication = GetConfidentialClientApplication(httpContext);
            if (request.Actor == null || request.Actor == Actor.User)
            {
                var userAccount = await GetUserAccountAsync(httpContext, confidentialClientApplication);
                var token = default(AuthenticationResult);
                if (userAccount != null)
                {
                    // There is a cached user account, attempt to silently acquire a token.
                    token = await confidentialClientApplication.AcquireTokenSilent(request.Scopes, userAccount).ExecuteAsync();
                }
                else
                {
                    // There is no cached user account, check if there is a bearer token.
                    // TODO-H: Check if this still works, and if the original bearer token can't be retrieved from the "saved" tokens.
                    var bearerToken = httpContext.User.FindFirst(OpenIdConnectIdentityProvider.ClaimTypeBearerToken)?.Value;
                    if (bearerToken != null)
                    {
                        token = await confidentialClientApplication.AcquireTokenOnBehalfOf(request.Scopes, new UserAssertion(bearerToken)).ExecuteAsync();
                    }
                }
                if (token != null)
                {
                    ValidateScopes(request.Scopes, token.Scopes);
                    return TokenResponse.Succeeded(token.AccessToken);
                }
            }
            else if (request.Actor == Actor.App)
            {
                var token = await confidentialClientApplication.AcquireTokenForClient(request.Scopes).ExecuteAsync();
                return TokenResponse.Succeeded(token.AccessToken);
            }
            else if (request.Actor == Actor.AzureManagedIdentity)
            {
                ArgumentNullException.ThrowIfNull(request.Scopes);
                var token = await new DefaultAzureCredential().GetTokenAsync(new TokenRequestContext(request.Scopes.ToArray()));
                return TokenResponse.Succeeded(token.Token);
            }
        }
        catch (Exception exc)
        {
            if (!ShouldUserReauthenticate(exc))
            {
                throw;
            }
        }
        return await GetTokenResponseForRedirectAsync(httpContext, request);
    }

    public virtual async Task<AuthenticationResult> RedeemAuthorizationCodeAsync(HttpContext httpContext, string authorizationCode)
    {
        var confidentialClientApplication = GetConfidentialClientApplication(httpContext);
        var scopes = Array.Empty<string>(); // No need to pass in scopes at this point, they were already requested during authorization.
        var token = await confidentialClientApplication.AcquireTokenByAuthorizationCode(scopes, authorizationCode).ExecuteAsync();
        ValidateScopes(scopes, token.Scopes);
        return token;
    }

    public virtual async Task RemoveUserAsync(HttpContext httpContext)
    {
        var confidentialClientApplication = GetConfidentialClientApplication(httpContext);
        var userAccount = await GetUserAccountAsync(httpContext, confidentialClientApplication);
        await confidentialClientApplication.RemoveAsync(userAccount);
    }

    protected virtual async Task<ClaimsPrincipal?> GetUserAsync(HttpContext httpContext)
    {
        var user = await httpContext.AuthenticateAsync(this.AuthenticationScheme);
        return user.Principal;
    }

    protected virtual async Task<IAccount?> GetUserAccountAsync(HttpContext httpContext, IConfidentialClientApplication confidentialClientApplication)
    {
        var user = await GetUserAsync(httpContext);
        if (user?.Identity != null && user.Identity.IsAuthenticated)
        {
            var accountId = user.FindFirst(ClaimTypeHomeAccountId)?.Value;
            if (!string.IsNullOrWhiteSpace(accountId))
            {
                return await confidentialClientApplication.GetAccountAsync(accountId);
            }
        }
        return null;
    }

    protected virtual void ValidateScopes(IEnumerable<string>? requestedScopes, IEnumerable<string>? returnedScopes)
    {
        // Even though the scopes are requested, they may not always be returned from a refresh token flow if the user
        // hasn't consented to a new scope yet; in that case, trigger a new interactive consent flow.
        if (requestedScopes == null || !requestedScopes.Any())
        {
            // No scopes were requested, valid.
            return;
        }
        // Don't check the presence of certain scopes that are requested but not returned (e.g. "offline_access").
        var requestedScopesToValidate = requestedScopes.Except(new[] { OpenIdConnectScope.OfflineAccess }, StringComparer.OrdinalIgnoreCase);
        if (returnedScopes == null || !requestedScopesToValidate.All(scope => returnedScopes.Any(s => string.Equals(s, scope, StringComparison.OrdinalIgnoreCase))))
        {
            // One or more scopes that were requested were not returned, invalid.
            // Throw an MsalUiRequiredException with a custom error code to signal to the exception handler that it should trigger.
            throw new MsalUiRequiredException(MsalUiRequiredExceptionErrorCodeRequestedScopeMissing, null);
        }
    }

    protected virtual IConfidentialClientApplication GetConfidentialClientApplication(HttpContext httpContext)
    {
        var confidentialClientApplication = GetConfidentialClientApplicationBuilder(httpContext).Build();
        confidentialClientApplication.AddInMemoryTokenCache();
        return confidentialClientApplication;
    }

    protected virtual ConfidentialClientApplicationBuilder GetConfidentialClientApplicationBuilder(HttpContext httpContext)
    {
        return ConfidentialClientApplicationBuilder.CreateWithApplicationOptions(new ConfidentialClientApplicationOptions
        {
            ClientId = this.Configuration.ClientId,
            ClientSecret = this.Configuration.ClientSecret,
            TenantId = this.tenantId,
            // TODO: When exchanging an authorization code for an access token, the RedirectUri needs to be set to the
            // same value as when the authorization code was requested.
            // We build it up dynamically here but perhaps it can be stored during the initial flow and and retrieved here.
            // See https://github.com/dotnet/aspnetcore/blob/ac39742bf152a0d2980059289822e1d3526a880a/src/Security/Authentication/OpenIdConnect/src/OpenIdConnectHandler.cs#L457.
            RedirectUri = UriHelper.BuildAbsolute(httpContext.Request.Scheme, httpContext.Request.Host, httpContext.Request.PathBase, this.LoginCallbackPath)
        });
    }

    protected virtual bool ShouldUserReauthenticate(Exception exc)
    {
        var msalUiRequiredException = exc as MsalUiRequiredException;
        if (msalUiRequiredException == null)
        {
            msalUiRequiredException = exc?.InnerException as MsalUiRequiredException;
        }

        if (msalUiRequiredException == null)
        {
            return false;
        }

        if (msalUiRequiredException.ErrorCode == MsalUiRequiredExceptionErrorCodeRequestedScopeMissing)
        {
            // A custom error code was used to explicitly signal that an interactive flow should be triggered.
            return true;
        }

        if (msalUiRequiredException.ErrorCode == MsalError.UserNullError)
        {
            // If the error code is "user_null", this indicates a cache problem.
            // When calling an [Authenticate]-decorated controller we expect an authenticated
            // user and therefore its account should be in the cache. However in the case of an
            // InMemoryCache, the cache could be empty if the server was restarted. This is why
            // the null_user exception is thrown.
            return true;
        }

        if (msalUiRequiredException.ErrorCode == MsalError.InvalidGrantError
            && msalUiRequiredException.Message.Contains("AADSTS65001", StringComparison.OrdinalIgnoreCase)
            && msalUiRequiredException.ResponseBody.Contains("consent_required", StringComparison.OrdinalIgnoreCase))
        {
            // The grant was invalid with a "suberror" indicating that consent is required.
            // This is typically the case with incremental consent, when requesteing an access token
            // for a permission that was not yet consented to.
            return true;
        }

        return false;
    }
}