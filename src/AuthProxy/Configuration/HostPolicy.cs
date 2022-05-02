namespace AuthProxy.Configuration;

public enum HostPolicy
{
    UseHostFromHttpRequest,
    UseHostFromBackendApp,
    UseConfiguredHostName
}