using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthProxy.ReverseProxy;

public static class Constants
{
    public static class Defaults
    {
        public const string CookiePrefix = ".AuthProxy.";
        public const string AuthenticationCookieName = CookiePrefix + "Authentication";
        public const bool AuthenticationCookieIsPersistent = false;
        public static readonly TimeSpan TokenIssuerExpiration = TimeSpan.FromHours(1);
        public const string ApiBasePath = ".auth/api";
        public const string ResponseType = OpenIdConnectResponseType.CodeIdToken; // Request an authorization code flow by default unless overridden in configuration
        public static readonly IList<string> TokenRequestScopes = new List<string> { OpenIdConnectScope.OfflineAccess }; // Request "offline_access" by default to get refresh tokens
        public const string LoginPath = "/.auth/login";
        public const string LoginCallbackPath = "/.auth/login/callback";
        public const string PostLoginReturnUrlQueryParameterName = "returnUrl"; // NOTE: App Service EasyAuth uses "post_login_redirect_uri".
        public const string LogoutPath = "/.auth/logout";
        public const string PostLogoutReturnUrlQueryParameterName = "returnUrl"; // NOTE: App Service EasyAuth uses "post_logout_redirect_uri".
        public const bool UsePkce = true; // Use PKCE by default unless overridden in configuration
        public const bool GetClaimsFromUserInfoEndpoint = false; // Don't get claims from the UserInfo endpoint by default unless overridden in configuration
    }

    public static class AuthenticationSchemes
    {
        public const string DefaultIdentityProvider = "(default)";
        public const string AuthProxy = nameof(AuthProxy);
    }

    public static class AuthenticationTypes
    {
        public const string Metadata = "AuthProxy.Metadata";
        public const string BackendApp = "AuthProxy.BackendApp";
        public const string UserInfo = "AuthProxy.UserInfo";
        public const string RoundTrip = "AuthProxy.RoundTrip";
    }

    public static class ClaimTypes
    {
        public const string IdentityProviderId = "idp.id";
        public const string IdentityProviderType = "idp.type";
        public const string BearerToken = "bearer_token";
    }

    public static class HttpHeaders
    {
        public const string Bearer = "Bearer";
    }

    public static class ApiPaths
    {
        public const string Token = "token";
        public const string Forward = "forward";
    }
}