namespace AuthProxy.Configuration;

public class BackendConfig
{
    public string? Url { get; set; }
    public string Audience { get; set; } = Defaults.BackendAppAudience;
}