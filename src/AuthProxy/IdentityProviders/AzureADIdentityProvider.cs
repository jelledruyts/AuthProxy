using System.Security.Claims;
using AuthProxy.Configuration;
using AuthProxy.Models;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Identity.Client;
using Microsoft.Identity.Web;

namespace AuthProxy.IdentityProviders;

// TODO-L: The "login_hint" claim (if present) of the current principal's "original" (federated) identity
// can be used as the "logout_hint" when a logout is requested towards the IdP.
// See https://docs.microsoft.com/azure/active-directory/develop/v2-protocols-oidc#send-a-sign-out-request.

public class AzureADIdentityProvider : OpenIdConnectIdentityProvider
{
    public const string ClaimTypeHomeAccountId = "msal_accountid";
    private const string MsalUiRequiredExceptionErrorCodeRequestedScopeMissing = "requested_scope_missing"; // A custom error code to signal that a requested scope was not granted (likely because it was not previously consented to).
    private readonly string tenantId;

    public AzureADIdentityProvider(IdentityProviderConfig configuration, string authenticationScheme, string loginPath, string loginCallbackPath, string postLoginReturnUrlQueryParameterName)
        : base(configuration, authenticationScheme, loginPath, loginCallbackPath, postLoginReturnUrlQueryParameterName)
    {
        ArgumentNullException.ThrowIfNull(configuration.Authority);
        this.tenantId = GetTenantId(configuration.Authority);
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

    protected override IList<string> GetDefaultClaimTransformations()
    {
        // Override IdP-specific claims transformations to include useful claims by default and to make other ones more meaningful.
        var claimTransformations = base.GetDefaultClaimTransformations();
        claimTransformations.Add("name=preferred_username");
        claimTransformations.Add("roles");
        claimTransformations.Add("email");
        return claimTransformations;
    }

    public async override Task<TokenResponse> GetTokenAsync(HttpContext httpContext, TokenRequest request)
    {
        // TODO-H: Check if request is for user or app.
        try
        {
            var confidentialClientApplication = GetConfidentialClientApplication(httpContext);
            var userAccount = await GetUserAccountAsync(httpContext.User, confidentialClientApplication);
            if (userAccount != null)
            {
                var token = await confidentialClientApplication.AcquireTokenSilent(request.Scopes, userAccount).ExecuteAsync();
                ValidateScopes(request.Scopes, token.Scopes);
                return new TokenResponse { Status = TokenResponseStatus.Succeeded, Token = token.AccessToken };
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
        var userAccount = await GetUserAccountAsync(httpContext.User, confidentialClientApplication);
        await confidentialClientApplication.RemoveAsync(userAccount);
    }

    protected virtual async Task<IAccount?> GetUserAccountAsync(ClaimsPrincipal? user, IConfidentialClientApplication confidentialClientApplication)
    {
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
        if (returnedScopes == null || !requestedScopes.All(scope => returnedScopes.Any(s => string.Equals(s, scope, StringComparison.OrdinalIgnoreCase))))
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