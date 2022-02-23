using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTBearerTokenTest
{
    public class JWTBearerTokenSettings
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string GrantType { get; set; }
        public string Scopes { get; set; }
        public string Purposes { get; set; }
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string RsaPublicKey { get; set; }
        public string RsaPrivateKey { get; set; }
    }
}
