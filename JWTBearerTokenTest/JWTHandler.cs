using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTBearerTokenTest
{
    public class JwtClaims
    {
        public string Subject { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string Acr { get; set; }
        public string Expiration { get; set; }
        public string IssuedAt { get; set; }
        public string JWTId { get; set; }
        public Dictionary<string, string> CustomFields { get; set; }        
    }

    public class JwtResponse
    {
        public string Token { get; set; }
        public long ExpiresAt { get; set; }
    }

    public interface IJwtHandler
    {
        JwtResponse CreateToken(JwtClaims claims);
        bool ValidateToken(string token);
    }

    public class JwtHandler : IJwtHandler
    {
        private readonly JWTBearerTokenSettings _settings;
        public JwtHandler(IOptions<JWTBearerTokenSettings> setting)
        {
            _settings = setting.Value;
        }

        public JwtResponse CreateToken(JwtClaims claims)
        {
            byte[] privateKey = _settings.RsaPrivateKey.ToByteArray();

            using RSA rsa = RSA.Create();
            rsa.ImportRSAPrivateKey(privateKey, out _);

            SigningCredentials signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            DateTime now = DateTime.Now;
            long unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();

            var jwt = new JwtSecurityToken(
                audience: _settings.Audience,
                issuer: _settings.Issuer,
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(nameof(claims.Sub), claims.Sub),
                    new Claim(nameof(claims.Scope), claims.Scope),
                    new Claim(nameof(claims.Purpose), claims.Purpose),
                    new Claim(nameof(claims.AuthenticationContext), claims.AuthenticationContext),
                    new Claim(nameof(claims.Acr), claims.Acr)
                },
                notBefore: now,
                expires: now.AddMinutes(5),
                signingCredentials: signingCredentials
            );

            string token = new JwtSecurityTokenHandler().WriteToken(jwt);

            return new JwtResponse
            {
                Token = token,
                ExpiresAt = unixTimeSeconds,
            };
        }

        public bool ValidateToken(string token)
        {
            byte[] publicKey = _settings.RsaPublicKey.ToByteArray();

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
                {
                    CacheSignatureProviders = false
                }
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;
        }

        public string GenerateLink(string token) =>
     $"{_settings.ReferralUrl}/{_settings.ReferralId}/foo?token={token}";

        public JwtResponse CreateToken(JwtClaims claims)
        {
            throw new NotImplementedException();
        }
    }
}