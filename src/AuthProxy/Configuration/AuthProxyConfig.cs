namespace AuthProxy.Configuration;

public class AuthProxyConfig
{
    public BackendConfig? Backend { get; set; }
    public PoliciesConfig? Policies { get; set; }
    public AuthenticationConfig? Authentication { get; set; }

    public void Validate()
    {
        // TODO: Check for empty strings and other validation rules everywhere.
        ArgumentNullException.ThrowIfNull(this.Backend);
        this.Backend.Validate();
        if (this.Policies != null)
        {
            this.Policies.Validate();
        }
        ArgumentNullException.ThrowIfNull(this.Authentication);
        this.Authentication.Validate();
    }
}