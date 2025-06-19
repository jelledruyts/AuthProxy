namespace AuthProxy.ReverseProxy.Configuration;

public class CookieConfig
{
    public string Name { get; set; } = Constants.Defaults.AuthenticationCookieName;
    public bool IsPersistent { get; set; } = Constants.Defaults.AuthenticationCookieIsPersistent;
}