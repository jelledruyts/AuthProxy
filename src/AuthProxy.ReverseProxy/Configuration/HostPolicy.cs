namespace AuthProxy.ReverseProxy.Configuration;

public enum HostPolicy
{
    UseHostFromHttpRequest,
    UseHostFromBackendApp,
    UseConfiguredHostName
}