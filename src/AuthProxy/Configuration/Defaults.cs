using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace AuthProxy.Configuration;

public static class Defaults
{
    public const string AuthenticationScheme = "(default)";
    public const string LoginPath = "/.auth/login";
    public const string LoginCallbackPath = "/.auth/login/callback";
    public const string PostLoginReturnUrlQueryParameterName = "returnUrl"; // NOTE: App Service EasyAuth uses "post_login_redirect_uri".
    public const string LogoutPath = "/.auth/logout";
    public const string PostLogoutReturnUrlQueryParameterName = "returnUrl"; // NOTE: App Service EasyAuth uses "post_logout_redirect_uri".
    public const string AuthenticationCookieName = ".AuthProxy";
    public const bool AuthenticationCookieIsPersistent = false;
    public const string BackendAppAudience = "AuthProxy.BackendApp";
    public const string TokenIssuerIssuer = "AuthProxy";
    public static readonly TimeSpan TokenIssuerExpiration = TimeSpan.FromHours(1);
    public const string ApiBasePath = ".auth/api";
    public const string ResponseType = OpenIdConnectResponseType.CodeIdToken; // Request an authorization code flow by default unless overridden in configuration
    public static readonly IList<string> TokenRequestScopes = new List<string> { OpenIdConnectScope.OfflineAccess }; // Request "offline_access" by default to get refresh tokens
}