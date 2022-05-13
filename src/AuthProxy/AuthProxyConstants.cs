namespace AuthProxy;

// This file is shared with the AuthProxy.Client project, so that constants can be
// maintained in one place, while still avoiding the projects to have a runtime
// dependency on each other.

public static partial class AuthProxyConstants
{
    public static class HttpHeaderNames
    {
        public const string CallbackAuthorizationHeaderName = "X-AuthProxy-Callback-AuthorizationHeader-Name";
        public const string CallbackAuthorizationHeaderValue = "X-AuthProxy-Callback-AuthorizationHeader-Value";
        public const string CallbackTokenEndpoint = "X-AuthProxy-Callback-TokenEndpoint";
        public const string CallbackForwardEndpoint = "X-AuthProxy-Callback-ForwardEndpoint";
        public const string Action = "X-AuthProxy-Action";
        public const string ReturnUrl = "X-AuthProxy-ReturnUrl";
        public const string Destination = "X-AuthProxy-Destination";
        public const string Status = "X-AuthProxy-Status";
        public const string RedirectUrl = "X-AuthProxy-RedirectUrl";
        public const string RedirectCookies = "X-AuthProxy-RedirectCookies";
    }

    public static class Actions
    {
        public const string Logout = "Logout";
    }

    public static class Defaults
    {
        public const string TokenIssuer = "AuthProxy";
        public const string TokenAudience = "AuthProxy.BackendApp";
        public const string NameClaimType = "name";
        public const string RoleClaimType = "roles";
    }
}