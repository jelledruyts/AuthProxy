namespace AuthProxy.Configuration;

public class BackendConfig
{
    public string? Url { get; set; }

    public void Validate()
    {
        ArgumentNullException.ThrowIfNull(this.Url);
    }
}