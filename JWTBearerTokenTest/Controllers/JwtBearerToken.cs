using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace JWTBearerTokenTest.Controllers
{
    public class JwtBearerToken : IJwtBearerToken
    {
        private JwtSecurityToken token;
        private string assertion;

        private readonly JWTBearerTokenSettings _settings;
        private readonly IHttpClientFactory _httpClientFactory;

        public string Assertion { get => assertion; }
        public JwtSecurityToken Token { get => token; }

        public JwtBearerToken(JWTBearerTokenSettings setting, IHttpClientFactory httpClientFactory)
        {
            _settings = setting;
            _httpClientFactory = httpClientFactory;
        }

        public async Task<string> GetBearerToken(string user_id, string identifier, bool phoneNumber)
        {
            assertion = GenerateAssertion(user_id, identifier, phoneNumber);
            string endpoint = "/token";

            Dictionary<string, string> formUrl = new Dictionary<string, string>()
            {
                { "grant_type", _settings.GrantType },
                { "assertion", assertion }
            };

            HttpClient client = _httpClientFactory.CreateClient("Token4P");

            HttpResponseMessage response = await client.PostAsync(endpoint, new FormUrlEncodedContent(formUrl));

            if (response.IsSuccessStatusCode)
            {
                string responseJson = await response.Content.ReadAsStringAsync();
                return JObject.Parse(responseJson)["access_token"].Value<string>();
            }
            else
            {
                return $"{response.StatusCode} - {await response.Content.ReadAsStringAsync()}";
            }
        }


        private string GenerateAssertion(string user_id, string identifier, bool phoneNumber)
        {
            DateTime now = DateTime.Now;
            DateTime exp = now.AddMinutes(5);

            byte[] privateKey = Base64UrlEncoder.DecodeBytes(_settings.RsaPrivateKey);

            RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            string typeIdentifier = phoneNumber ? "phone_number" : "uid";
            string authenticationContext = "[{\"identifier\":\"" + identifier + "\",\"type\":\"" + typeIdentifier + "\"}]";
            string acr = (phoneNumber) ? "2" : "3";

            List<Claim> claims = new List<Claim>()
            {
                new Claim(JwtRegisteredClaimNames.Sub, user_id),
                new Claim("scope", _settings.Scopes),
                new Claim("purpose", _settings.Purposes),
                new Claim("authentication_context", authenticationContext, JsonClaimValueTypes.JsonArray),
                new Claim(JwtRegisteredClaimNames.Acr, acr),
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            token = new JwtSecurityToken(
               issuer: _settings.Issuer,
               audience: _settings.Audience,
               claims: claims,
               notBefore: null,
               expires: exp,
               signingCredentials: new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
