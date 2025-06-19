namespace AuthProxy;

public static class AuthProxyConstants
{
    public static class HttpHeaderNames
    {
        private const string Prefix = "X-AuthProxy-";
        public const string CallbackHeaderPrefix = Prefix + "Callback-Header-";
        public const string CallbackTokenEndpoint = Prefix + "Callback-TokenEndpoint";
        public const string CallbackForwardEndpoint = Prefix + "Callback-ForwardEndpoint";
        public const string Action = Prefix + "Action";
        public const string ReturnUrl = Prefix + "ReturnUrl";
        public const string Destination = Prefix + "Destination";
        public const string Status = Prefix + "Status";
        public const string RedirectUrl = Prefix + "RedirectUrl";
        public const string RedirectCookies = Prefix + "RedirectCookies";
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

    public static class UrlPaths
    {
        public const string AuthProxyConfiguration = "/.well-known/authproxy-configuration";
    }
}