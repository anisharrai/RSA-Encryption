using System.Security.Cryptography;
using System.Text;

namespace RSAEncryption
{
    public class EncryptionDecryptionService
    {
        public KeyPair GenerateKeyPair()
        {
            //2048 bits = 256 bytes
            using var rsa = new RSACryptoServiceProvider(2048);
            return new KeyPair
            {
                PublicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey()),
                PrivateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey())
            };
        }

        public string Encrypt(string plainText, string publicKey)
        {
            //using doesnot require braces {} , object is disposed at the end of its scope
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKey), out _);
            var encryptedData = rsa.Encrypt(Encoding.UTF8.GetBytes(plainText), RSAEncryptionPadding.Pkcs1);
            return Convert.ToBase64String(encryptedData);
            // Code using rsa
            // rsa.Dispose() is called automatically here, at the end of the method.
        }


        public string Decrypt(string cipherText, string privateKey)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out _);
            var decryptedData = rsa.Decrypt(Convert.FromBase64String(cipherText), RSAEncryptionPadding.Pkcs1);
            return Encoding.UTF8.GetString(decryptedData);

        }
    }
}