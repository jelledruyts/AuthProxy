namespace AuthProxy.Models;

// This file is shared with the AuthProxy.Client project, so that models can be
// maintained in one place, while still avoiding the projects to have a runtime
// dependency on each other.

public class TokenResponse
{
    public TokenResponseStatus Status { get; set; }
    public string? ErrorMessage { get; set; }
    public string? Token { get; set; }
    public string? RedirectUrl { get; set; }
    public IList<string>? RedirectCookies { get; set; }

    public static TokenResponse Succeeded(string token)
    {
        return new TokenResponse
        {
            Status = TokenResponseStatus.Succeeded,
            Token = token
        };
    }

    public static TokenResponse Failed(string? errorMessage)
    {
        return new TokenResponse
        {
            Status = TokenResponseStatus.Failed,
            ErrorMessage = string.IsNullOrWhiteSpace(errorMessage) ? "Failed to acquire token" : errorMessage
        };
    }
}