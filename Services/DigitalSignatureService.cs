using System.Security.Cryptography;
using System.Text;

namespace RSAEncryption.Services
{
    public class DigitalSignatureService
    {

        /// <summary>
        /// Signs a message  using a provate key 
        ///Takes a message and private key, signs the message, and returns a Base64-encoded signature.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public string SignData(string message, string privateKey)
        {
            using var rsa = new RSACryptoServiceProvider();
            //convert privateKey from base64-encoded sting -> byte[] array 
            //as ImportRSAPrivateKey requires bytes.
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
            
            var dataBytes = Encoding.UTF8.GetBytes(message);
            var signedData = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            //converts an array of 8-bit unsigned integers -> base64 string representation
            return Convert.ToBase64String(signedData);
        }

        /// <summary>
        /// verifies a messages signature using a public key 
        /// </summary>
        /// <param name="message"></param>
        /// <param name="signature"></param>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public bool VerifySignature(string message, string signature , string publicKey)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
            //Convert Message and Signature to Bytes
            var dataBytes = Encoding.UTF8.GetBytes(message);
            var signatureBytes = Convert.FromBase64String(signature);
            return rsa.VerifyData(dataBytes, signatureBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        }
    }
}
