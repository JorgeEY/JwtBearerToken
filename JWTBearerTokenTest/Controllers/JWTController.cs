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
using System.Net.Http;
using System.Threading.Tasks;

namespace JWTBearerTokenTest.Controllers
{
    [Route("api/jwt")]
    public class JWTController : Controller
    {
        private readonly ILogger<JWTController> _logger;
        private readonly JWTBearerTokenSettings _settings;
        private readonly IHttpClientFactory _httpClientFactory;

        public JWTController(ILogger<JWTController> logger, IOptions<JWTBearerTokenSettings> setting, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _settings = setting.Value;
            _httpClientFactory = httpClientFactory;
        }

        [HttpPost]
        [Route("token")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public async Task<IActionResult> GetBearerToken([FromBody] JwtClaims claims)
        {
            string token = GenerateJwt(claims);
            string endpoint = "/token";

            Dictionary<string, string> formurl = new Dictionary<string, string>();
            formurl.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
            formurl.Add("assertion", token);

            HttpClient client = _httpClientFactory.CreateClient("Token4P");

            HttpResponseMessage response = await client.PostAsync(endpoint, new FormUrlEncodedContent(formurl));

            if (response.IsSuccessStatusCode)
            {
                return Ok(await response.Content.ReadAsStringAsync());
            }
            else
            {
                return BadRequest($"{response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
            }
        }

        private string GenerateJwt(JwtClaims claims)
        {
            DateTime now = DateTime.Now;
            DateTime exp = now.AddMinutes(5);

            byte[] privateKey = Base64UrlEncoder.DecodeBytes(_settings.RsaPrivateKey);

            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            string aa = JsonSerializer.Serialize(claims.AuthenticationContext);

            Claim[] neededClaims = new[] {
                    new Claim(JwtRegisteredClaimNames.Sub, claims.Subject),
                    new Claim("scope", claims.Scope),
                    new Claim("purpose", claims.Purpose),
                    new Claim("authentication_context", JsonSerializer.Serialize(claims.AuthenticationContext), JsonClaimValueTypes.JsonArray),
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

            return t;
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
            JwtSecurityToken t = handler.ReadJwtToken(token.token);

            return Ok(validatedSecurityToken);
        }
    }
}
