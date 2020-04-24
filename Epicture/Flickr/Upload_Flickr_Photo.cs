using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace Epicture
{
    internal class UploadFlickrPhoto
    {
        private readonly string Secret = string.Empty;
        private readonly string SecretAccesToken = string.Empty;

        public UploadFlickrPhoto(string accesprivToken, string secret)
        {
            SecretAccesToken = accesprivToken;
            Secret = secret;
        }

        public event EventHandler<UploadProgressEventArgs> OnUploadProgress;

        public string OAuthCalculateAuthHeader(Dictionary<string, string> parameters)
        {
            var sb = new StringBuilder("OAuth ");
            foreach (var pair in parameters)
                if (pair.Key.StartsWith("oauth", StringComparison.Ordinal))
                    sb.Append(pair.Key + "=\"" + Uri.EscapeDataString(pair.Value) + "\",");
            return sb.Remove(sb.Length - 1, 1).ToString();
        }


        public async Task<string> UploadDataAsync(Stream imageStream, string fileName, Uri uploadUri,
            Dictionary<string, string> parameters)
        {
            var boundary = "FLICKR_MIME_" + DateTime.Now.ToString("yyyyMMddhhmmss", DateTimeFormatInfo.InvariantInfo);
            var authHeader = OAuthCalculateAuthHeader(parameters);
            var dataBuffer = CreateUploadData(imageStream, fileName, parameters, boundary);
            var req = (HttpWebRequest) WebRequest.Create(uploadUri);
            req.Method = "POST";
            req.ContentType = "multipart/form-data; boundary=" + boundary;
            if (!string.IsNullOrEmpty(authHeader))
                req.Headers["Authorization"] = authHeader;
            req.AllowReadStreamBuffering = false;
            try
            {
                using (var reqStream = await req.GetRequestStreamAsync())
                {
                    var bufferSize = 32 * 1024;
                    if (dataBuffer.Length / 100 > bufferSize) bufferSize = bufferSize * 2;
                    dataBuffer.UploadProgress += (o, e) =>
                    {
                        if (OnUploadProgress != null) OnUploadProgress(this, e);
                    };
                    dataBuffer.CopyTo(reqStream, bufferSize);
                    reqStream.Flush();
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
            catch (Exception e)
            {
                return null;
            }
        }

        private StreamCollection CreateUploadData(Stream imageStream, string fileName,
            Dictionary<string, string> parameters, string boundary)
        {
            var oAuth = parameters.ContainsKey("oauth_consumer_key");

            var keys = new string[parameters.Keys.Count];
            parameters.Keys.CopyTo(keys, 0);
            Array.Sort(keys);

            var hashStringBuilder = new StringBuilder(SecretAccesToken, 2 * 1024);
            var ms1 = new MemoryStream();
            var contentStringBuilder = new StreamWriter(ms1, new UTF8Encoding(false));

            foreach (var key in keys)
            {
#if !SILVERLIGHT
                // Silverlight < 5 doesn't support modification of the Authorization header, so all data must be sent in post body.
                if (key.StartsWith("oauth", StringComparison.Ordinal)) continue;
#endif
                hashStringBuilder.Append(key);
                hashStringBuilder.Append(parameters[key]);
                contentStringBuilder.Write("--" + boundary + "\r\n");
                contentStringBuilder.Write("Content-Disposition: form-data; name=\"" + key + "\"\r\n");
                contentStringBuilder.Write("\r\n");
                contentStringBuilder.Write(parameters[key] + "\r\n");
            }

            if (!oAuth)
            {
                contentStringBuilder.Write("--" + boundary + "\r\n");
                contentStringBuilder.Write("Content-Disposition: form-data; name=\"api_sig\"\r\n");
                contentStringBuilder.Write("\r\n");
                contentStringBuilder.Write(MD5Hash(hashStringBuilder.ToString()) + "\r\n");
            }

            // Photo
            contentStringBuilder.Write("--" + boundary + "\r\n");
            contentStringBuilder.Write("Content-Disposition: form-data; name=\"photo\"; filename=\"" +
                                       Path.GetFileName(fileName) + "\"\r\n");
            contentStringBuilder.Write("Content-Type: image/jpg\r\n");
            contentStringBuilder.Write("\r\n");

            contentStringBuilder.Flush();

            var photoContents = ConvertNonSeekableStreamToByteArray(imageStream);

            var ms2 = new MemoryStream();
            var postFooterWriter = new StreamWriter(ms2, new UTF8Encoding(false));
            postFooterWriter.Write("\r\n--" + boundary + "--\r\n");
            postFooterWriter.Flush();

            var collection = new StreamCollection(new[] {ms1, photoContents, ms2});

            return collection;
        }

        private static Stream ConvertNonSeekableStreamToByteArray(Stream nonSeekableStream)
        {
            if (nonSeekableStream.CanSeek)
            {
                nonSeekableStream.Position = 0;
                return nonSeekableStream;
            }
            return nonSeekableStream;
        }


        public static string MD5Hash(string data)
        {
#if SILVERLIGHT
            hashedBytes = MD5Core.GetHash(data, Encoding.UTF8);
#else

            var strAlgName = HashAlgorithmNames.Md5;
            var buff = CryptographicBuffer.ConvertStringToBinary(data, BinaryStringEncoding.Utf8);
            var objAlgProv = HashAlgorithmProvider.OpenAlgorithm(strAlgName);
            var buffHash = objAlgProv.HashData(buff);
            if (buffHash.Length != objAlgProv.HashLength)
                throw new Exception("There was an error creating the hash");
            var hex = CryptographicBuffer.EncodeToHexString(buffHash);


#endif
            return hex;
        }


        internal static string EscapeDataString(string value)
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

        public static string EscapeOAuthString(string text)
        {
            var value = text;

            value = EscapeDataString(value).Replace("+", "%20");

            // UrlEncode escapes with lowercase characters (e.g. %2f) but oAuth needs %2F
            value = Regex.Replace(value, "(%[0-9a-f][0-9a-f])", c => c.Value.ToUpper());

            // these characters are not escaped by UrlEncode() but needed to be escaped
            value = value.Replace("(", "%28").Replace(")", "%29").Replace("$", "%24").Replace("!", "%21").Replace(
                "*", "%2A").Replace("'", "%27");

            // these characters are escaped by UrlEncode() but will fail if unescaped!
            value = value.Replace("%7E", "~");

            return value;
        }

        public string OAuthCalculateSignature(string method, string url, Dictionary<string, string> parameters,
            string tokenSecret)
        {
            var baseString = "";
            var key = Secret + "&" + tokenSecret;
            var keyBytes = Encoding.UTF8.GetBytes(key);

#if !SILVERLIGHT
            var sorted = new SortedList<string, string>();
            foreach (var pair in parameters) sorted.Add(pair.Key, pair.Value);
#else
                var sorted = parameters.OrderBy(p => p.Key);
#endif

            var sb = new StringBuilder();
            foreach (var pair in sorted)
            {
                sb.Append(pair.Key);
                sb.Append("=");
                sb.Append(EscapeOAuthString(pair.Value));
                sb.Append("&");
            }

            sb.Remove(sb.Length - 1, 1);

            baseString = method + "&" + EscapeOAuthString(url) + "&" + EscapeOAuthString(sb.ToString());

#if WindowsCE
            FlickrNet.Security.Cryptography.HMACSHA1 sha1 = new FlickrNet.Security.Cryptography.HMACSHA1(keyBytes);
#else
            var sha1 = new HMACSHA1(keyBytes);
#endif

            var hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(baseString));

            var hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        public class UploadProgressEventArgs : EventArgs
        {
            internal UploadProgressEventArgs()
            {
            }

            internal UploadProgressEventArgs(long bytes, long totalBytes)
            {
                BytesSent = bytes;
                TotalBytesToSend = totalBytes;
            }

            /// <summary>
            ///     Number of bytes transfered so far.
            /// </summary>
            public long BytesSent { get; internal set; }

            /// <summary>
            ///     Total bytes to be sent. -1 if this is unknown.
            /// </summary>
            public long TotalBytesToSend { get; internal set; }

            /// <summary>
            ///     True if all bytes have been uploaded.
            /// </summary>
            public bool UploadComplete
            {
                get { return ProcessPercentage == 100; }
            }

            /// <summary>
            ///     The percentage of the upload that has been completed.
            /// </summary>
            public int ProcessPercentage
            {
                get { return Convert.ToInt32(BytesSent * 100 / TotalBytesToSend); }
            }
        }

        internal class StreamCollection : IDisposable
        {
            public EventHandler<UploadProgressEventArgs> UploadProgress;

            public StreamCollection(IEnumerable<Stream> streams)
            {
                Streams = new List<Stream>(streams);
            }

            public List<Stream> Streams { get; }

            public long? Length
            {
                get
                {
                    long l = 0;
                    foreach (var s in Streams)
                    {
                        if (!s.CanSeek) return null;

                        l += s.Length;
                    }
                    return l;
                }
            }

            public void Dispose()
            {
                Streams.ForEach(s =>
                {
                    if (s != null)
                        s.Dispose();
                });
            }

            public void ResetPosition()
            {
                Streams.ForEach(s =>
                {
                    if (s.CanSeek) s.Position = 0;
                });
            }

            public void CopyTo(Stream stream, int bufferSize = 1024 * 16)
            {
                ResetPosition();

                var buffer = new byte[bufferSize];
                var l = Length;
                var soFar = 0;

                foreach (var s in Streams)
                {
                    int read;
                    while (0 < (read = s.Read(buffer, 0, buffer.Length)))
                    {
                        soFar += read;
                        stream.Write(buffer, 0, read);
                        if (UploadProgress != null)
                            UploadProgress(this,
                                new UploadProgressEventArgs
                                {
                                    BytesSent = soFar,
                                    TotalBytesToSend = l.GetValueOrDefault(-1)
                                });
                    }
                    stream.Flush();
                }
                stream.Flush();
            }
        }
    }
}