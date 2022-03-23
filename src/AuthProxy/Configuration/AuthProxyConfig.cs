namespace AuthProxy.Configuration;

public class AuthProxyConfig
{
    public static AuthProxyConfig? Instance { get; set; }
    
    public BackendConfig? Backend { get; set; }
    public AuthenticationConfig? Authentication { get; set; }

    public void Validate()
    {
        // TODO: Check for empty strings and other validation rules everywhere.
        ArgumentNullException.ThrowIfNull(this.Backend);
        this.Backend.Validate();
        ArgumentNullException.ThrowIfNull(this.Authentication);
        this.Authentication.Validate();
    }
}