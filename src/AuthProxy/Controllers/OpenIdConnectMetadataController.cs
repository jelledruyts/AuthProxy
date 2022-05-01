using System.Security.Cryptography;
using AuthProxy.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

namespace AuthProxy.Controllers;

[ApiController]
public class OpenIdConnectMetadataController : ControllerBase
{
    private readonly TokenIssuer tokenIssuer;
    private readonly IList<JsonWebKey> keys;

    public OpenIdConnectMetadataController(TokenIssuer tokenIssuer)
    {
        this.tokenIssuer = tokenIssuer;
        this.keys = new List<JsonWebKey>(this.tokenIssuer.SigningCredentials.Count);
        foreach (var signingCredential in this.tokenIssuer.SigningCredentials)
        {
            var x509Key = (X509SecurityKey)signingCredential.Key;
            var rsa = (RSA)x509Key.PublicKey;
            var parameters = rsa.ExportParameters(false);
            var key = new JsonWebKey
            {
                kty = "RSA",
                use = "sig",
                kid = x509Key.KeyId,
                x5t = WebEncoders.Base64UrlEncode(x509Key.Certificate.GetCertHash()),
                e = WebEncoders.Base64UrlEncode(parameters.Exponent!),
                n = WebEncoders.Base64UrlEncode(parameters.Modulus!),
                x5c = new[] { Convert.ToBase64String(x509Key.Certificate.RawData) },
                alg = signingCredential.Algorithm
            };
            this.keys.Add(key);
        }
    }

    [Route("/.well-known/openid-configuration")]
    public ActionResult GetOpenIdConfiguration()
    {
        // Provide minimal OIDC configuration metadata that allows the backend app
        // and the Auth Proxy API endpoint itself to validate incoming JWT tokens.
        var metadata = new
        {
            issuer = this.tokenIssuer.Issuer,
            jwks_uri = this.Url.ActionLink(nameof(GetKeys), null, null, this.Request.Scheme, this.Request.Host.Value, null)
        };
        return Ok(metadata);
    }

    [Route("/.well-known/openid-keys")]
    public ActionResult GetKeys()
    {
        var metadata = new
        {
            keys = this.keys
        };
        return Ok(metadata);
    }

    private class JsonWebKey
    {
        public string? kty { get; set; }
        public string? use { get; set; }
        public string? kid { get; set; }
        public string? x5t { get; set; }
        public string? e { get; set; }
        public string? n { get; set; }
        public string[]? x5c { get; set; }
        public string? alg { get; set; }
    }
}