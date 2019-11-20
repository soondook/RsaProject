using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
namespace EncryptRsa
{
    class Program
    {

        static async Task Main(string[] args)
        {

            string decrypt = "RncLoZTcX1Gjlyus/y0Lis0NT29Y1BwClU1nhXSZQF+KGxcTBLnkIcAlLU6Nm9BJL382HZXiG95bql1BE3IHYg3G3k/qRcGIa6N26hAwTgJVUgCyPhXNmlzz2B7DfhvCnWKxy031XG650FwtUYY7FwwpN3aDspRO2lkargx1J5w=";
            string encrypt = "12345678";
            object KeyResult;
            string xmlParams;
            KeyResult = await Web_Request.MakeAsyncRequestc(key: "");
            xmlParams = KeyResult.ToString();
            Encrypt_RSA.EncryptRsa(encrypt, xmlParams);
            Encrypt_RSA.DecryptRsa(decrypt, xmlParams);
        }
    }
    class Encrypt_RSA
    {
        public static void EncryptRsa(string encrypt, string xmlParams)
        {
            //Console.WriteLine(xmlParams);
            // Text to encrypt and decrypt.
            Console.WriteLine(encrypt);
            // Use OAEP padding (PKCS#1 v2).
            var doOaepPadding = true;
            // ------------------------------------------------
            // RSA Keys
            // ------------------------------------------------
            var rsa = new RSACryptoServiceProvider();
            // Import parameters from XML string.
            rsa.FromXmlString(xmlParams);
            // Export RSA key to RSAParameters and include:
            //    false - Only public key required for encryption.
            //    true  - Private key required for decryption.
            // Export parameters and include only Public Key (Modulus + Exponent) required for encryption.
            var rsaParamsPublic = rsa.ExportParameters(false);
            // Export Public Key (Modulus + Exponent) and include Private Key (D) required for decryption.
            var rsaParamsPrivate = rsa.ExportParameters(true);
            // ------------------------------------------------
            // Encrypt
            // ------------------------------------------------
            var decryptedBytes = Encoding.UTF8.GetBytes(encrypt);
            // Create a new instance of RSACryptoServiceProvider.
            //rsa = new RSACryptoServiceProvider();
            // Import the RSA Key information.
            rsa.ImportParameters(rsaParamsPublic);
            // Encrypt byte array.
            var encryptedBytes = rsa.Encrypt(decryptedBytes, doOaepPadding);
            // Convert bytes to base64 string.
            var encryptedString = Convert.ToBase64String(encryptedBytes);
            rsa.Dispose();
            
            Console.WriteLine(encryptedString);
            // ------------------------------------------------
            
        }

        public static void DecryptRsa(string decrypt, string xmlParams) {
            // Decrypt
            // ------------------------------------------------
            var doOaepPadding = true;
            // ------------------------------------------------
            // RSA Keys
            // ------------------------------------------------
            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(xmlParams);
            var rsaParamsPrivate = rsa.ExportParameters(true);
            // Convert base64 string back to bytes.
            var encryptedBytes = Convert.FromBase64String(decrypt);
            // Create a new instance of RSACryptoServiceProvider.
            // Import the RSA Key information.
            rsa.ImportParameters(rsaParamsPrivate);
            // Decrypt byte array.
            var decryptedBytes = rsa.Decrypt(encryptedBytes, doOaepPadding);
            // Get decrypted data.
            string ResultDecrypt = Encoding.UTF8.GetString(decryptedBytes);
            rsa.Dispose();
            Console.WriteLine(ResultDecrypt);
            // ------------------------------------------------

        }


        /// <summary>
        /// Import OpenSSH PEM private key string into MS RSACryptoServiceProvider
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        /*
        public static RSACryptoServiceProvider ImportPrivateKey(string pem)
        {
            TextWriter outputStream = new StreamWriter("C:\\temp\\rsakey");
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            RSAParameters rsaParams = DotNetUtilities.ToRSAParameters((RsaPrivateCrtKeyParameters)KeyPair.Private);

            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParams);
            //csp.ToXmlString(true);
            Console.WriteLine(csp.ToXmlString(true));
            //ExportPrivateKey(csp, outputStream);
            outputStream.Write(csp.ToXmlString(true));
            outputStream.Dispose();
            //ImportPublicKey(pem);
            return csp;
        }

        /// <summary>
        /// Import OpenSSH PEM public key string into MS RSACryptoServiceProvider
        /// 
        public static RSACryptoServiceProvider ImportPublicKey(string pub)
        {
            TextWriter PublicKey = new StreamWriter("C:\\temp\\PublicKey");
            PemReader pr2 = new PemReader(new StringReader(pub));
            AsymmetricCipherKeyPair KeyPair = (AsymmetricCipherKeyPair)pr2.ReadObject();
            RSAParameters rsaParam = DotNetUtilities.ToRSAParameters((RsaKeyParameters)KeyPair.Public);
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider();// cspParams);
            csp.ImportParameters(rsaParam);
            Console.WriteLine(csp.ToXmlString(false));
            PublicKey.Write(csp.ToXmlString(false));
            PublicKey.Dispose();
            return csp;
        }
    }
    */
    }
        class Web_Request
        {
            public static async Task<object> MakeAsyncRequestc(string key)
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://10.61.145.115/ServiceKeys.php");
                request.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
                request.Method = "POST"; // для отправки используется метод Post
                string data = "";
                byte[] byteArray = Encoding.UTF8.GetBytes(data);
                request.ContentType = "text/html,application/xhtml+xml,application/xml;";
                request.Timeout = 500000;
                request.ContentLength = byteArray.Length;
                //записываем данные в поток запроса

                using (Stream dataStream = request.GetRequestStream())
                {
                    dataStream.Write(byteArray, 0, byteArray.Length);
                }
                try
                {
                    var response = await request.GetResponseAsync();
                    //var returns = response.GetResponseStream();
                    using (Stream stream = response.GetResponseStream())
                    {
                        using (StreamReader reader = new StreamReader(stream))
                        {
                            string responsedata = reader.ReadToEnd();
                            var keys = responsedata.ToString();
                            key = keys.TrimEnd('}');
                        Console.WriteLine(key);
                        //key.Substring(key.Length-2);
                        byte[] file = Encoding.UTF8.GetBytes(responsedata);
                            FileStream fs = new FileStream("C:\\temp\\resp.txt", FileMode.Create);
                            fs.Write(file, 0, file.Length);
                            fs.Flush();
                            fs.Dispose();
                        }

                    }
                    response.Close();
                }
                catch (WebException ex)
                {
                    //Return any exception messages back to the Response header
                    var StatusCode = HttpStatusCode.InternalServerError;
                    Console.WriteLine(StatusCode.ToString());
                    var StatusDescription = ex.Message.Replace("\r\n", "");
                    LogMessage(StatusDescription.ToString(), "c:\\Temp\\error_resp.txt");
                    LogMessage(StatusCode.ToString(), "c:\\Temp\\error_resp.txt");
                 }
                catch (Exception e)
                {
                    var StatusDescription = e.Message.Replace("\r\n", "");
                    LogMessage(StatusDescription.ToString(), "c:\\Temp\\error_resp.txt");
                }

                finally
                {
                }
            return key;

        }
            public static void LogMessage(string Message, string FileName)
            {
                try
                {
                    Console.WriteLine("write Error...");
                    using (TextWriter tw = new StreamWriter(FileName, true))
                    {
                        tw.WriteLine(DateTime.Now.ToString() + " - " + Message);
                    }
                }
                catch (Exception ex)  //Writing to log has failed, send message to trace in case anyone is listening.
                {
                    System.Diagnostics.Trace.Write(ex.ToString());
                }
            }


        }
    }


