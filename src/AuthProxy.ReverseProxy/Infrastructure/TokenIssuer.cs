using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using AuthProxy.ReverseProxy.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace AuthProxy.ReverseProxy.Infrastructure;

public class TokenIssuer
{
    public const string ApiAudience = "AuthProxy.API";
    private readonly TimeSpan expiration;
    private readonly JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
    public string Audience { get; }
    public string Issuer { get; }
    public IList<SigningCredentials> SigningCredentials { get; } = new List<SigningCredentials>();

    public TokenIssuer(AuthProxyConfig config)
    {
        this.Audience = config.Backend.Audience;
        this.Issuer = config.TokenIssuer.Issuer;
        this.expiration = config.TokenIssuer.Expiration;
        if (config.TokenIssuer.SigningCertificates.Count == 0)
        {
            throw new ArgumentOutOfRangeException("There are no signing certificates configured for the token issuer.");
        }
        foreach (var certificateConfig in config.TokenIssuer.SigningCertificates)
        {
            ArgumentNullException.ThrowIfNull(certificateConfig.Path);
            var certificate = new X509Certificate2(certificateConfig.Path, certificateConfig.Password);
            var signingKey = new X509SecurityKey(certificate);
            this.SigningCredentials.Add(new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));
        }
    }

    public string CreateToken(ClaimsIdentity identity, string? audience = null)
    {
        return CreateToken(identity.Claims, audience);
    }

    public string CreateToken(IEnumerable<Claim> claims, string? audience = null)
    {
        return CreateToken(claims.DistinctBy(c => c.Type).ToDictionary(c => c.Type, c => (object)c.Value), audience);
    }

    public string CreateToken(IDictionary<string, object> claims, string? audience = null)
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
            Claims = claims
        };

        var token = this.tokenHandler.CreateToken(tokenDescriptor);
        return this.tokenHandler.WriteToken(token);
    }
}