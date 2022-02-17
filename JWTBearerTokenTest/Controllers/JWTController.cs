using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using static Microsoft.AspNetCore.Http.StatusCodes;

namespace JWTBearerTokenTest.Controllers
{
    [Route("api/jwt")]
    public class JWTController : Controller
    {
        private readonly ILogger<JWTController> _logger;

        public JWTController(ILogger<JWTController> logger)
        {
            _logger = logger;
        }

        [HttpPost]
        [Route("token")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult GenerateJwt()
        {
            var claims = new JwtCustomClaims
            {
                Sub = "",
                Scope = "",
                Purpose = "",
                AuthenticationContext = "",
                Acr = ""
            };

            var jwt = _jwtHandler.CreateToken(claims);

            //var link = _jwtHandler.GenerateLink(jwt.Token);

            return Ok(jwt);
        }

        /*[HttpPost]
        [Route("token/validate")]
        [ProducesResponseType(typeof(string), Status200OK)]
        /*public IActionResult ValidateJwt([FromBody] string token)
        {

            if (_jwtHandler.ValidateToken(token))
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                var claims = new JwtCustomClaims
                {
                    FirstName = jwtToken.Claims.First(claim => claim.Type == "FirstName").Value,
                    LastName = jwtToken.Claims.First(claim => claim.Type == "LastName").Value,
                    Email = jwtToken.Claims.First(claim => claim.Type == "Email").Value
                };

                return Ok(claims);
            }

            return BadRequest("Token is invalid.");
        }*/
    }
}
