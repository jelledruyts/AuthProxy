using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthProxy.Infrastructure;

public class TokenIssuer
{
    private readonly string audience;
    private readonly string issuer;
    private readonly TimeSpan expiration;
    private readonly JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
    private readonly SigningCredentials signingCredentials;

    public TokenIssuer(string audience, string issuer, TimeSpan expiration, string signingSecret)
    {
        this.audience = audience;
        this.issuer = issuer;
        this.expiration = expiration;
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingSecret));
        this.signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256Signature);
    }

    public string CreateToken(IEnumerable<Claim> claims)
    {
        return this.CreateToken(claims, this.audience, this.issuer, this.expiration);
    }

    public string CreateToken(IEnumerable<Claim> claims, string audience, string issuer, TimeSpan expiration)
    {
        var nowUtc = DateTime.UtcNow;
        var issuedUtc = nowUtc.AddMinutes(-5); // Account for clock skew.

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Audience = audience,
            Expires = nowUtc.Add(expiration),
            IssuedAt = issuedUtc,
            Issuer = issuer,
            NotBefore = issuedUtc,
            SigningCredentials = this.signingCredentials,
            Subject = new ClaimsIdentity(claims)
        };

        var token = this.tokenHandler.CreateToken(tokenDescriptor);
        return this.tokenHandler.WriteToken(token);
    }
}