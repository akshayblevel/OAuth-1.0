using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Web;
using System.Web.Http;

namespace OAuth1.Controllers
{
    public class AuthController : ApiController
    {
    //Get Token
        public IEnumerable<string> Get()
        {
            string normalizedUrl = string.Empty;
            string normalizedParameters = string.Empty;
            string consumerKey = "key";
            string consumerSecret = "secret";
            Uri uri = new Uri("https://www.mywebsite1.com");

            OAuthBase oAuth = new OAuthBase();
            string nonce = oAuth.GenerateNonce();
            string timeStamp = oAuth.GenerateTimeStamp();
            string sig = oAuth.GenerateSignature(uri,
                consumerKey, consumerSecret,
                string.Empty, string.Empty,
                "GET", timeStamp, nonce,
            OAuthBase.SignatureTypes.HMACSHA1, out normalizedUrl, out normalizedParameters);

            sig = HttpUtility.UrlEncode(sig);

            StringBuilder sb = new StringBuilder(uri.ToString());
            sb.AppendFormat("?oauth_consumer_key={0}&", consumerKey);
            sb.AppendFormat("oauth_nonce={0}&", nonce);
            sb.AppendFormat("oauth_timestamp={0}&", timeStamp);
            sb.AppendFormat("oauth_signature_method={0}&", "HMAC-SHA1");
            sb.AppendFormat("oauth_version={0}&", "1.0");
            sb.AppendFormat("oauth_signature={0}", sig);

            return new string[] { sb.ToString(), normalizedUrl, normalizedParameters };
        }

        [Route("validate")]
        public HttpResponseMessage Validate([FromBody]Data data)
        {
            // Get all required parameter to generate signature except secret key and generate signature
            // Compare signature to signature
            // Note: secret key should be retrieved from DB based on consumer key.

            return null;
        }
    }

     public class Data
    { }
}
