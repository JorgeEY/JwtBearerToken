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

            byte[] privateKey = Convert.FromBase64String(_settings.RsaPrivateKey);

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            SigningCredentials signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            JwtPayload payload = new JwtPayload()
            {
                {"sub", claims.Subject },
                {"aud", _settings.Audience  },
                {"scope", claims.Scope },
                {"purpose", claims.Purpose },
                {"authentication_context", JsonSerializer.Serialize(claims.AuthenticationContext) },
                {"acr", claims.Acr },
                {"iss", _settings.Issuer},
                {"exp", new DateTimeOffset(exp).ToUnixTimeSeconds() },
                {"iat", new DateTimeOffset(now).ToUnixTimeSeconds() },
                {"jti", Guid.NewGuid().ToString() }
            };

            JwtHeader header = new JwtHeader(signingCredentials);

            JwtSecurityToken token = new JwtSecurityToken(header, payload);
            
            return Ok(token);
        }
    }
}
