using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using AuthProxy.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthProxy.Infrastructure;

public class TokenIssuer
{
    public const string ApiAudience = "AuthProxy.API";
    private readonly TimeSpan expiration;
    private readonly JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
    public string Audience { get; }
    public string Issuer { get; }
    public IList<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

    public TokenIssuer(TokenIssuerConfig config)
    {
        this.Audience = config.Audience;
        this.Issuer = config.Issuer;
        this.expiration = config.Expiration;
        if (config.SigningCertificates.Count == 0)
        {
            throw new ArgumentOutOfRangeException("There are no signing certificates configured for the token issuer.");
        }
        foreach (var certificateConfig in config.SigningCertificates)
        {
            ArgumentNullException.ThrowIfNull(certificateConfig.Path);
            var certificate = new X509Certificate2(certificateConfig.Path, certificateConfig.Password);
            var signingKey = new X509SecurityKey(certificate);
            this.SigningCredentials.Add(new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));
        }
    }

    public string CreateToken(ClaimsIdentity identity, string? audience = null)
    {
        var nowUtc = DateTime.UtcNow;
        var issuedUtc = nowUtc.AddMinutes(-5); // Account for clock skew.

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Audience = audience ?? this.Audience,
            Expires = nowUtc.Add(this.expiration),
            IssuedAt = issuedUtc,
            Issuer = this.Issuer,
            NotBefore = issuedUtc,
            SigningCredentials = this.SigningCredentials.First(),
            Subject = identity
        };

        var token = this.tokenHandler.CreateToken(tokenDescriptor);
        return this.tokenHandler.WriteToken(token);
    }
}