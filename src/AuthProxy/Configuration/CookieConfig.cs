namespace AuthProxy.Configuration;

public class CookieConfig
{
    public string? Name { get; set; } = Defaults.AuthenticationCookieName;

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(this.Name);
    }
}