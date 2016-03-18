/**                            **
**  Made By Jonathan Abraham   **
**  18/03/2016                 **
**                             **
**                             */             

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace AESLibrary
{
    public class AESCore
    {
        #region Properties

        public string AlgName { get; private set; }
        public uint KeySize { get; set; }
        public BinaryStringEncoding Encoding { get; set; }

        #endregion

        #region Init
        public AESCore()
        {
            Encoding = BinaryStringEncoding.Utf8;
            AlgName = SymmetricAlgorithmNames.AesCbcPkcs7;
            KeySize = 512;
        }

        #endregion

        #region Bytes
        public IBuffer Encrypt(IBuffer toEncryptBuffer, string key)
        {
            try
            {
                // Get the MD5 key hash (you can as well use the binary of the key string)
                var keyHash = GetMD5Hash(key);

                // Open a symmetric algorithm provider for the specified algorithm.
                var aes = SymmetricKeyAlgorithmProvider.OpenAlgorithm(AlgName);

                // Create a symmetric key.
                var symetricKey = aes.CreateSymmetricKey(keyHash);

                var buffEncrypted = CryptographicEngine.Encrypt(symetricKey, toEncryptBuffer, null);

                return buffEncrypted;
            }
            catch (Exception)
            {
                throw;
            }
        }


        public IBuffer Decrypt(IBuffer toDecryptBuffer, string key)
        {
            try
            {
                // Get the MD5 key hash (you can as well use the binary of the key string)
                var keyHash = GetMD5Hash(key);

                // Create a buffer that contains the encoded message to be decrypted.
                

                // Open a symmetric algorithm provider for the specified algorithm.
                SymmetricKeyAlgorithmProvider aes = SymmetricKeyAlgorithmProvider.OpenAlgorithm(AlgName);

                // Create a symmetric key.
                var symetricKey = aes.CreateSymmetricKey(keyHash);

                IBuffer buffDecrypted = CryptographicEngine.Decrypt(symetricKey, toDecryptBuffer, null);

                return buffDecrypted;
            }
            catch (Exception)
            {
                throw;
            }
        }

        #endregion

        #region String

        public string Encrypt(string toEncrypt, string key)
        {
            // Create a buffer that contains the encoded message to be encrypted.
            var toEncryptBuffer = CryptographicBuffer.ConvertStringToBinary(toEncrypt, BinaryStringEncoding.Utf8);

            IBuffer bufferEncrypted = Encrypt(toEncryptBuffer, key);
            return CryptographicBuffer.EncodeToBase64String(bufferEncrypted);
        }

        public string Decrypt(string toDecrypt, string key)
        {
            IBuffer toDecryptBuffer = CryptographicBuffer.DecodeFromBase64String(toDecrypt);
            return CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8, Decrypt(toDecryptBuffer, key));
        }

        #endregion

        #region Helpers

        private static IBuffer GetMD5Hash(string key)
        {
            // Convert the message string to binary data.
            IBuffer buffUtf8Msg = CryptographicBuffer.ConvertStringToBinary(key, BinaryStringEncoding.Utf8);

            // Create a HashAlgorithmProvider object.
            HashAlgorithmProvider objAlgProv = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);

            // Hash the message.
            IBuffer buffHash = objAlgProv.HashData(buffUtf8Msg);

            // Verify that the hash length equals the length specified for the algorithm.
            if (buffHash.Length != objAlgProv.HashLength)
            {
                throw new Exception("There was an error creating the hash");
            }

            return buffHash;
        }

        #endregion
    }
}
