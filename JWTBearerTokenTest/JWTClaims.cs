using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTBearerTokenTest
{
    public class AuthenticationContext
    {
        public string identifier { get; set; }
        public string type { get; set; }
    }
    public class JwtClaims
    {
        public string Subject { get; set; }
        public string Acr { get; set; }
        public string Scope { get; set; }
        public string Purpose { get; set; }
        public List<AuthenticationContext> AuthenticationContext { get; set; }
    }

    public class JwtToken
    {
        public string token { get; set; }
    }
}
