namespace AuthProxy.Models;

public class TokenResponse
{
    public TokenResponseStatus Status { get; set; }
    public string? Token { get; set; }
    public string? RedirectUrl { get; set; }
    public string[]? RedirectCookies { get; set; }
}