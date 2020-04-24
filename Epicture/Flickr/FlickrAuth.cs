using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Windows.Data.Xml.Dom;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.UI.Popups;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Media.Imaging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Epicture
{
    public class FlickrAuth : Page
    {
        private const string PostContentType = "application/x-www-form-urlencoded";

        private static string Secret;
        private static string ConsumerKey;
        private static string oauth_result_token_pub;
        private static string oauth_result_token_priv;
        public List<BitmapImage> bitmap = new List<BitmapImage>();
        public string nsid;
        public string OAuthAccessToken;
        public string OAuthAccessTokenSecret;
        public string username;

        public FlickrAuth()
        {
            Secret = "7b50037a5958fff3";
            ConsumerKey = "a715ad0fa59f73296c3b3b14e581bfc2";
            oauth_result_token_pub = string.Empty;
            oauth_result_token_priv = string.Empty;
            OAuthAccessToken = string.Empty;
            OAuthAccessTokenSecret = string.Empty;
            username = string.Empty;
            nsid = string.Empty;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Gets options for controlling the authentication. </summary>
        /// Getter sur les différents paramètre nécessaire a l'OAuth Flickr
        /// <value> Options that control the authentication. </value>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private Dictionary<string, string> OAuthParameters
        {
            get
            {
                var random = new Random();
                var epochDate = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
                var timeSpan = DateTime.UtcNow - epochDate;
                var oauthTimestamp =
                    timeSpan.TotalSeconds.ToString(NumberFormatInfo.InvariantInfo);
                var oauthNonce = random.Next(1000).ToString();
                var parameters = new Dictionary<string, string>
                {
                    {"oauth_nonce", oauthNonce},
                    {"oauth_signature_method", "HMAC-SHA1"},
                    {"oauth_timestamp", oauthTimestamp},
                    {"oauth_version", "1.0"}
                };
                return parameters;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Gets longin link. </summary>
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// Permet de logger l'user en retournant l'url d'authentification du service Flickr
        /// <returns>   The longin link. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        public async Task<string> GetLonginLink()
        {
            var baseUrlForRequesttoken = "https://secure.flickr.com/services/oauth/request_token";

            //Obtention des paramètres
            var parameters = OAuthParameters;
            parameters.Add("oauth_consumer_key", ConsumerKey);
            parameters.Add("oauth_callback", "http://www.example.com/");
            //Obtention de l'url Signé
            var signedUrl = CalculateOAuthSignedUrl(parameters, baseUrlForRequesttoken, Secret, false);

            //envoie de l'url a flickr
            var response = await GetResponseFromWeb(signedUrl);
            SetRequestToken(response);
            // checktoken(oauth_result_token_pub);
            return "https://secure.flickr.com/services/oauth/authorize?oauth_token=" + oauth_result_token_pub +
                   "&perms=delete";
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Calculates the o authentication signed URL. </summary>
        /// Permet de générer la signature de l'url voulu
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// <param name="parameters">   Paramètre de la string build pour la requête (Résultat du getter) </param>
        /// <param name="url">          URL Flickr pour la requête voulu </param>
        /// <param name="exchangeStep"> True to exchange step. </param>
        /// <returns>   The calculated o authentication signed URL. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private string CalculateOAuthSignedUrl(Dictionary<string, string> parameters, string url, string secret,
            bool exchangeStep)
        {
            var baseString = new StringBuilder();
            string baseStringForSig;
            var sortedParams = new SortedDictionary<string, string>();
            IBuffer keyMaterial;

            foreach (var param in parameters)
                sortedParams.Add(param.Key, param.Value);

            foreach (var param in sortedParams)
            {
                baseString.Append(param.Key);
                baseString.Append("=");
                baseString.Append(Uri.EscapeDataString(param.Value));
                baseString.Append("&");
            }

            //removing the extra ampersand 
            baseString.Remove(baseString.Length - 1, 1);
            baseStringForSig = "GET&" + Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(baseString.ToString());

            //calculating the signature 
            var HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");

            if (exchangeStep)
                keyMaterial = CryptographicBuffer.ConvertStringToBinary(Secret + "&" + secret, BinaryStringEncoding.Utf8);
            else
                keyMaterial = CryptographicBuffer.ConvertStringToBinary(secret + "&", BinaryStringEncoding.Utf8);

            var cryptoKey = HmacSha1Provider.CreateKey(keyMaterial);
            var dataString = CryptographicBuffer.ConvertStringToBinary(baseStringForSig, BinaryStringEncoding.Utf8);

            return url + "?" + baseString + "&oauth_signature=" +
                   Uri.EscapeDataString(
                       CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Sign(cryptoKey, dataString)));
        }

        /// <summary>
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="url"></param>
        /// <param name="secret"></param>
        /// <param name="exchangeStep"></param>
        /// <returns></returns>
        private string CalculateOAuthSignedUrlPOST(Dictionary<string, string> parameters, string url, string secret,
            bool exchangeStep)
        {
            var baseString = new StringBuilder();
            string baseStringForSig;
            var sortedParams = new SortedDictionary<string, string>();
            IBuffer keyMaterial;

            foreach (var param in parameters)
                sortedParams.Add(param.Key, param.Value);

            foreach (var param in sortedParams)
            {
                baseString.Append(param.Key);
                baseString.Append("=");
                baseString.Append(Uri.EscapeDataString(param.Value));
                baseString.Append("&");
            }

            //removing the extra ampersand 
            baseString.Remove(baseString.Length - 1, 1);
            baseStringForSig = "GET&" + Uri.EscapeDataString(url) + "&" + Uri.EscapeDataString(baseString.ToString());

            //calculating the signature 
            var HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");

            if (exchangeStep)
                keyMaterial = CryptographicBuffer.ConvertStringToBinary(Secret + "&" + secret, BinaryStringEncoding.Utf8);
            else
                keyMaterial = CryptographicBuffer.ConvertStringToBinary(secret + "&", BinaryStringEncoding.Utf8);

            var cryptoKey = HmacSha1Provider.CreateKey(keyMaterial);
            var dataString = CryptographicBuffer.ConvertStringToBinary(baseStringForSig, BinaryStringEncoding.Utf8);

            return url + "?" + baseString + "&oauth_signature=" +
                   Uri.EscapeDataString(
                       CryptographicBuffer.EncodeToBase64String(CryptographicEngine.Sign(cryptoKey, dataString)));
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Gets response from web. </summary>
        /// Génère la requête GET vers Flickr et renvoie la réponse par un Stream
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// <param name="url">  URL Flickr pour la requête voulu. </param>
        /// <returns>   The response from web. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private async Task<string> GetResponseFromWeb(string url)
        {
            try
            {
                var Request = (HttpWebRequest) WebRequest.Create(url);
                string httpResponse = null;
                Request.Method = "GET";
                var response = (HttpWebResponse) await Request.GetResponseAsync();
                if (response != null)
                {
                    var data = new StreamReader(response.GetResponseStream());
                    httpResponse = await data.ReadToEndAsync();
                }
                return httpResponse;
            }
            catch (Exception e)
            {
                var msgDialog = new MessageDialog("GetReponseFromWeb Failure\n" + e.Message);
                return null;
            }
        }

        /// <summary>
        /// </summary>
        /// <param name="url"></param>
        /// <returns></returns>
        private async Task<string> GetResponseFromWebPOST(string url)
        {
            try
            {
                var Request = (HttpWebRequest) WebRequest.Create(url);
                string httpResponse = null;
                Request.Method = "POST";
                var response = (HttpWebResponse) await Request.GetResponseAsync();
                if (response != null)
                {
                    var data = new StreamReader(response.GetResponseStream());
                    httpResponse = await data.ReadToEndAsync();
                }
                return httpResponse;
            }
            catch (Exception e)
            {
                var msgDialog = new MessageDialog("GetReponseFromWeb Failure\n" + e.Message);
                return null;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Sets request token. </summary>
        /// Permet de récupérer le oauth_token et le oauth_token_private
        /// necessaire pour le accessToken
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// <param name="response"> The response. </param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private static void SetRequestToken(string response)
        {
            var keyValPairs = response.Split('&');
            for (var i = 0; i < keyValPairs.Length; i++)
            {
                var splits = keyValPairs[i].Split('=');
                switch (splits[0])
                {
                    case "oauth_token":
                    {
                        oauth_result_token_pub = splits[1];
                        break;
                    }
                    case "oauth_token_secret":
                    {
                        oauth_result_token_priv = splits[1];
                        break;
                    }
                }
            }
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Gets access token. </summary>
        /// Permet de récupérer le token verifier et le oauth_token une fois logger
        /// sur l'API Flickr via le WebAuthBroker
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// <param name="responseData">
        ///     Retour url une fois logger sur Flickr, contient les différents tokens
        /// </param>
        /// <returns>   The access token. </r eturns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        public async Task GetAccessToken(string responseData)
        {
            string oauth_token = null;
            string oauth_verifier = null;
            var keyValPairs = responseData.Split('&');
            var baseUrlForAccessToken = "https://secure.flickr.com/services/oauth/access_token";

            //parses the response string 
            for (var i = 0; i < keyValPairs.Length; i++)
            {
                var splits = keyValPairs[i].Split('=');
                if (splits[0].Contains("oauth_token"))
                    oauth_token = splits[1];
                else if (splits[0].Contains("oauth_verifier"))
                    oauth_verifier = splits[1];
            }

            //Get basic parameters 
            var parameters = OAuthParameters;
            parameters.Add("oauth_callback", "http://www.example.com/");
            parameters.Add("oauth_consumer_key", ConsumerKey);
            parameters.Add("oauth_verifier", oauth_verifier);
            parameters.Add("oauth_token", oauth_token);
            var signedUrl = CalculateOAuthSignedUrl(parameters, baseUrlForAccessToken, oauth_result_token_priv, true);
            var response = await GetResponseFromWeb(signedUrl);
            CalculateAccessToken(response);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Calculates the access token. </summary>
        /// Récupère le résultat de la requête acces_token
        /// set les différentes propriétés aux valeurs récupérés
        /// <remarks>   Alexis Lina, 21/02/2017. </remarks>
        /// <param name="responseData">
        ///     Retour url une fois logger sur Flickr, contient les différents
        ///     tokens.
        /// </param>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private void CalculateAccessToken(string responseData)
        {
            var keyValPairs = responseData.Split('&');
            for (var i = 0; i < keyValPairs.Length; i++)
            {
                var splits = keyValPairs[i].Split('=');
                switch (splits[0])
                {
                    case "oauth_token":
                        OAuthAccessToken = splits[1];
                        break;
                    case "oauth_token_secret":
                        OAuthAccessTokenSecret = splits[1];
                        break;
                    case "username":
                        username = splits[1];
                        break;
                }
            }
            // Set current access token. 
            var roamingSettings = ApplicationData.Current.RoamingSettings;
            var composite = new ApplicationDataCompositeValue
            {
                ["accessToken"] = OAuthAccessToken,
                ["accessTokenSecret"] = OAuthAccessTokenSecret,
                ["username"] = username
            };
            roamingSettings.Values["accessCompositeSetting"] = composite;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Flickr o authentication request. </summary>
        /// Permet de tester si la méthode de login fonctionne avec une autre url
        /// Permet aussi de récuprérer l'id de l'utilisateur ainsi que le statut de la requête
        /// qui sont necessaire pour le reste des requêtes de 'lAPI.
        /// <remarks>   Alexis Lina, 22/02/2017. </remarks>
        /// <returns>   A Task. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        public async Task FlickrOAuthRequest()
        {
            var baseUrlForAccessToken = "https://api.flickr.com/services/rest";
            var parameter = OAuthParameters;
            parameter.Add("oauth_callback", "http://www.example.com/");
            parameter.Add("oauth_consumer_key", ConsumerKey);
            parameter.Add("nojsoncallback", "1");
            parameter.Add("format", "json");
            parameter.Add("oauth_token", OAuthAccessToken);
            parameter.Add("method", "flickr.test.login");
            var signedURL = CalculateOAuthSignedUrl(parameter, baseUrlForAccessToken, OAuthAccessTokenSecret, true);
            var response = await GetResponseFromWeb(signedURL);
            var rss = JObject.Parse(response);
            nsid = (string) rss["user"]["id"];
            var resStat = (string) rss["stat"];
        }

        /// <summary>
        /// </summary>
        /// <returns></returns>
        public async Task<RootObject> GetPublicPhoto()
        {
            var baseUrlForGetPhoto = "https://api.flickr.com/services/rest";
            var parameter = new Dictionary<string, string>
            {
                {"api_key", ConsumerKey},
                {"user_id", nsid},
                {"format", "json"},
                {"safe_search", "1"},
                {"method", "flickr.people.getPublicPhotos"}
            };
            var signedUrl = UrlBuilder(parameter, baseUrlForGetPhoto);
            var response = await GetResponseFromWeb(signedUrl);
            response = ReformatStringFlickrCall(response);
            var root = JsonConvert.DeserializeObject<RootObject>(response);
            return root;
        }

        /// <summary>
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="filename"></param>
        /// <returns></returns>
        public async Task<string> UploadPhotoFlickr(Stream stream, string filename)
        {
            var baseUriUpload = "https://api.flickr.com/services/upload/";
            var parameter = new Dictionary<string, string>();
            parameter = OAuthParameters;

            var uploadPhoto = new UploadFlickrPhoto(OAuthAccessTokenSecret, Secret);
            if (!string.IsNullOrEmpty(OAuthAccessToken))
            {
                parameter = OAuthParameters;
                parameter.Add("oauth_token", OAuthAccessToken);
                parameter.Add("oauth_consumer_key", ConsumerKey);
                parameter.Add("title", filename);
                var sig = uploadPhoto.OAuthCalculateSignature("POST", baseUriUpload, parameter, OAuthAccessTokenSecret);
                parameter.Add("oauth_signature", sig);
            }
            else
            {
                parameter.Add("auth_token", OAuthAccessToken);
            }

            var res = await uploadPhoto.UploadDataAsync(stream, filename, new Uri(baseUriUpload), parameter);
            var xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(res);
            var node = xmlDoc.SelectSingleNode("/rsp/@stat");
            return node.InnerText;
        }

        /// <summary>
        /// </summary>
        /// <param name="response"></param>
        /// <returns></returns>
        private string ReformatStringFlickrCall(string response)
        {
            var res2 = response.Replace("jsonFlickrApi(", "");
            var res3 = res2.Replace(")", "");
            return res3;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   URL builder. </summary>
        /// Permet de Build n'importe qu'elle requête URL vers l'API Flickr
        /// <remarks>   Alexis Lina, 22/02/2017. </remarks>
        /// <param name="UrlToBuild">   The URL to build. </param>
        /// <param name="url">          URL Flickr pour la requête voulu. </param>
        /// <returns>   A string. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////
        private string UrlBuilder(Dictionary<string, string> UrlToBuild, string url)
        {
            var baseString = new StringBuilder();
            string baseStringForSig;
            var sortedParams = new SortedDictionary<string, string>();

            foreach (var param in UrlToBuild)
                sortedParams.Add(param.Key, param.Value);

            foreach (var param in sortedParams)
            {
                baseString.Append(param.Key);
                baseString.Append("=");
                baseString.Append(param.Value);
                baseString.Append("&");
            }

            //removing the extra ampersand 
            baseString.Remove(baseString.Length - 1, 1);
            baseStringForSig = "POST&" + Uri.EscapeDataString(url) + "&" + baseString;
            return url + "?" + baseString;
        }

        public async void AddToFav(string photoId)
        {
            var baseUriAddFav = "https://api.flickr.com/services/rest";
            var parameters = new Dictionary<string, string>();
            parameters = OAuthParameters;
            parameters.Add("oauth_consumer_key", ConsumerKey);
            parameters.Add("oauth_token", OAuthAccessToken);
            parameters.Add("method", "flickr.favorites.add");
            parameters.Add("photo_id", "32195208694");
            var signedURL = CalculateOAuthSignedUrlPOST(parameters, baseUriAddFav, OAuthAccessTokenSecret, true);
            var response = await GetResponseFromWebPOST(signedURL);
        }

        public async Task<RootObject> GetPublicFav()
        {
            var baseUriAddFav = "https://api.flickr.com/services/rest";
            var parameters = new Dictionary<string, string>();
            parameters = OAuthParameters;
            parameters.Add("oauth_consumer_key", ConsumerKey);
            parameters.Add("oauth_token", OAuthAccessToken);
            parameters.Add("format", "json");

            parameters.Add("method", "flickr.favorites.getList");
            var signedURL = CalculateOAuthSignedUrlPOST(parameters, baseUriAddFav, OAuthAccessTokenSecret, true);
            var response = await GetResponseFromWebPOST(signedURL);
            response = ReformatStringFlickrCall(response);
            var root = JsonConvert.DeserializeObject<RootObject>(response);
            return root;
        }

        public async Task<string> DeleteFav(String idPhoto)
        {
            var baseUriAddFav = "https://api.flickr.com/services/rest";
            var parameters = new Dictionary<string, string>();
            var uploadPhoto = new UploadFlickrPhoto(OAuthAccessTokenSecret, Secret);
            if (!string.IsNullOrEmpty(OAuthAccessTokenSecret))
            {

                parameters = OAuthParameters;
                parameters.Add("oauth_consumer_key", ConsumerKey);
                parameters.Add("oauth_token", OAuthAccessToken);
                parameters.Add("photo_id", idPhoto);
                parameters.Add("method", "flickr.favorites.remove");
            }
            var signedUri = CalculateOAuthSignedUrl(parameters, baseUriAddFav, OAuthAccessTokenSecret, true);
            var method = "POST";
            var data = OAuthCalculatePostData(parameters);
            var authHeader = uploadPhoto.OAuthCalculateAuthHeader(parameters);
            try
            {
                var res = await DownloadData(method, signedUri, data, PostContentType, authHeader);
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(res);
                var node = xmlDoc.SelectSingleNode("/rsp/@stat");
                return node.InnerText;
            }
            catch (Exception e)
            {
                
                MessageDialog msg_failure = new MessageDialog(e.Message + "\n Problème suppresion photo favorite");
                return null;
            }

        }

        /// <summary>
        /// </summary>
        /// <param name="IdPhoto"></param>
        /// <returns></returns>
        public async Task<string> deleteImageFlicr(string IdPhoto)
        {
            var baseUriDel = "https://api.flickr.com/services/rest";
            var parameters = new Dictionary<string, string>();
            var uploadPhoto = new UploadFlickrPhoto(OAuthAccessTokenSecret, Secret);
            var method = "POST";
            string signed = null;
            if (!string.IsNullOrEmpty(OAuthAccessToken))
            {
                parameters = OAuthParameters;
                parameters.Add("oauth_consumer_key", ConsumerKey);
                parameters.Add("oauth_token", OAuthAccessToken);
                parameters.Add("photo_id", IdPhoto);
                parameters.Add("method", "flickr.photos.delete");
                signed = CalculateOAuthSignedUrlPOST(parameters, baseUriDel, OAuthAccessTokenSecret, true);
            }

            var data = OAuthCalculatePostData(parameters);
            var authHeader = uploadPhoto.OAuthCalculateAuthHeader(parameters);
            try
            {
                var res = await DownloadData(method, signed, data, PostContentType, authHeader);
                var xmlDoc = new XmlDocument();
                xmlDoc.LoadXml(res);
                var node = xmlDoc.SelectSingleNode("/rsp/@stat");
                return node.InnerText;
            }
            catch (Exception e)
            {
                throw;
            }
        }

        private async Task<string> DownloadData(string method, string baseUrl, string data, string contentType,
            string authHeader)
        {
            var boundary = "FLICKR_MIME_" + DateTime.Now.ToString("yyyyMMddhhmmss", DateTimeFormatInfo.InvariantInfo);
            var req = (HttpWebRequest) WebRequest.Create(baseUrl);
            req.ContentType = "multipart/form-data; boundary=" + boundary;
            req.AllowReadStreamBuffering = false;
            if (!string.IsNullOrEmpty(authHeader))
            {
                req.Headers["Content-Type"] = contentType;
                req.Headers["Authorization"] = authHeader;
            }
            var res = await req.GetResponseAsync();
            var toto = (HttpWebResponse) res;
            var stream = toto.GetResponseStream();
            if (stream == null)
                return null;

            var sr = new StreamReader(stream);
            var s = sr.ReadToEnd();
            sr.Dispose();
            return s;
        }

        /// <summary>
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        private static string OAuthCalculatePostData(Dictionary<string, string> parameters)
        {
            var data = string.Empty;
            foreach (var pair in parameters)
            {
                // Silverlight < 5 doesn't support modification of the Authorization header, so all data must be sent in post body.
#if SILVERLIGHT
                data += pair.Key + "=" + UtilityMethods.EscapeOAuthString(pair.Value) + "&";
#else
                if (!pair.Key.StartsWith("oauth", StringComparison.Ordinal))
                    data += pair.Key + "=" + EscapeDataString(pair.Value) + "&";
#endif
            }
            return data;
        }

        /// <summary>
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        private static string EscapeDataString(string value)
        {
            var limit = 2000;
            var sb = new StringBuilder(value.Length + value.Length / 2);
            var loops = value.Length / limit;

            for (var i = 0; i <= loops; i++)
                if (i < loops)
                    sb.Append(Uri.EscapeDataString(value.Substring(limit * i, limit)));
                else
                    sb.Append(Uri.EscapeDataString(value.Substring(limit * i)));

            return sb.ToString();
        }

        #region Deserializer JSON CLASS

        public class Photo
        {
            public string Id { get; set; }
            public string Owner { get; set; }
            public string Secret { get; set; }
            public string Server { get; set; }
            public int Farm { get; set; }
            public string Title { get; set; }
            public int Ispublic { get; set; }
            public int Isfriend { get; set; }
            public int Isfamily { get; set; }
        }

        public class Photos
        {
            public int Page { get; set; }
            public int Pages { get; set; }
            public int Perpage { get; set; }
            public string Total { get; set; }
            public List<Photo> Photo { get; set; }
        }

        public class RootObject
        {
            public Photos Photos { get; set; }
            public string Stat { get; set; }
        }

        #endregion
    }
}