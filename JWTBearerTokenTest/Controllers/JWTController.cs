using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.IdentityModel.Tokens.Jwt;
using static Microsoft.AspNetCore.Http.StatusCodes;
using Microsoft.Extensions.Options;
using System.Text.Json;
using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Security.Claims;

namespace JWTBearerTokenTest.Controllers
{
    [Route("api/jwt")]
    public class JWTController : Controller
    {
        private readonly ILogger<JWTController> _logger;
        private readonly JWTBearerTokenSettings _settings;

        public JWTController(ILogger<JWTController> logger, IOptions<JWTBearerTokenSettings> setting)
        {
            _logger = logger;
            _settings = setting.Value;
        }

        [HttpPost]
        [Route("token")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult GenerateJwt([FromBody] JwtClaims claims)
        {
            DateTime now = DateTime.Now;
            DateTime exp = now.AddMinutes(5);

            byte[] privateKey = Base64UrlEncoder.DecodeBytes(_settings.RsaPrivateKey);

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            Claim[] neededClaims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, claims.Subject),
                    new Claim("scope", claims.Scope),
                    new Claim("purpose", claims.Purpose),
                    new Claim("authentication_context", JsonSerializer.Serialize(claims.AuthenticationContext)),
                    new Claim(JwtRegisteredClaimNames.Acr, claims.Acr),
                    new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

            JwtSecurityToken token = new JwtSecurityToken(
               issuer: _settings.Issuer,
               audience: _settings.Audience,
               claims: neededClaims,
               notBefore: null,
               expires: exp,
               signingCredentials: new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            );

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();

            string t = handler.WriteToken(token);

            return Ok(t);
        }

        [HttpPost]
        [Route("validate")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult ValidateJwt([FromBody] JwtToken token)
        {
            byte[] publicKey = Base64UrlEncoder.DecodeBytes(_settings.RsaPublicKey);

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPublicKey(publicKey, out _);

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _settings.Issuer,
                ValidAudience = _settings.Audience,
                IssuerSigningKey = new RsaSecurityKey(rsa),
                CryptoProviderFactory = new CryptoProviderFactory()
            };

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            handler.ValidateToken(token.token, validationParameters, out var validatedSecurityToken);

            return Ok(validatedSecurityToken);
        }
    }
}
