namespace AuthProxy.Models;

// This file is shared with the AuthProxy.Client project, so that models can be
// maintained in one place, while still avoiding the projects to have a runtime
// dependency on each other.

public class TokenResponse
{
    public TokenResponseStatus Status { get; set; }
    public string? Token { get; set; }
    public string? RedirectUrl { get; set; }
    public IList<string>? RedirectCookies { get; set; }
}