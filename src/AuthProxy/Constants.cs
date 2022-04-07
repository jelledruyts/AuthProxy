namespace AuthProxy;

public static class Constants
{
    public static class AuthenticationTypes
    {
        public const string Metadata = "AuthProxy-Metadata";
        public const string BackendApp = "AuthProxy-BackendAppIdentity";
    }

    public static class ClaimTypes
    {
        public static class Metadata
        {
            public const string IdentityProviderName = "idp.name";
            public const string IdentityProviderType = "idp.type";
        }
    }
}