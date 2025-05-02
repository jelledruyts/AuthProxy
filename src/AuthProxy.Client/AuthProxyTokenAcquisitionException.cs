using AuthProxy.Models;

namespace AuthProxy.Client;

[Serializable]
public class AuthProxyTokenAcquisitionException : Exception
{
    public TokenResponse? TokenResponse { get; }

    public AuthProxyTokenAcquisitionException()
        : base()
    {
    }

    public AuthProxyTokenAcquisitionException(TokenResponse tokenResponse)
        : this(tokenResponse, "A token could not be acquired: " + tokenResponse.Status.ToString(), null)
    {
    }

    public AuthProxyTokenAcquisitionException(TokenResponse tokenResponse, string? message, Exception? inner)
        : base(message, inner)
    {
        this.TokenResponse = tokenResponse;
    }
}