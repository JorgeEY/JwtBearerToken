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
        private JwtBearerToken token;

        public JWTController(ILogger<JWTController> logger, IOptions<JWTBearerTokenSettings> setting, IHttpClientFactory httpClientFactory)
        {
            _logger = logger;
            _settings = setting.Value;
            _httpClientFactory = httpClientFactory;
            token = new JwtBearerToken(_settings, _httpClientFactory);
        }

        [HttpGet]
        [Route("token")]
        public async Task<IActionResult> GetToken(string user_id, string identifier, bool phoneNumber)
        {
            return Ok(await token.GetBearerToken(user_id, identifier, phoneNumber));
        }
    }
}
