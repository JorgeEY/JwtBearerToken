using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTBearerTokenTest
{
    public class JWTBearerTokenSettings
    {
        public string Audience { get; set; }
        public string Issuer { get; set; }
        public string RsaPublicKey { get; set; }
        public string RsaPrivateKey { get; set; }
    }
}
