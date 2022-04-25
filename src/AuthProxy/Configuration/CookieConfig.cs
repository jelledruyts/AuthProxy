namespace AuthProxy.Configuration;

public class CookieConfig
{
    public string Name { get; set; } = Defaults.AuthenticationCookieName;
    public bool IsPersistent { get; set; } = Defaults.AuthenticationCookieIsPersistent;
}