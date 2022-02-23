using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;

namespace JWTBearerTokenTest.Controllers
{
    public interface IJwtBearerToken
    {
        string Assertion { get; }
        JwtSecurityToken Token { get; }
        Task<string> GetBearerToken(string user_id, string identifier, bool phoneNumber);
    }
}