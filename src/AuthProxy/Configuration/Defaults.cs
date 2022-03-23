namespace AuthProxy.Configuration;

public static class Defaults
{
    public const string AuthenticationScheme = "(default)";
    public const string LoginPath = "/.auth/login";
    public const string LoginCallbackPath = "/.auth/login/callback";
    public const string LogoutPath = "/.auth/logout";
    public const string AuthenticationCookieName = ".AuthProxy";
    public static readonly TimeSpan TokenIssuerExpiration = TimeSpan.FromHours(1);
}