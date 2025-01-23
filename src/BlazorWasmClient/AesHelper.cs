using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace BlazorWasmClient
{
    public class AesHelper
    {
        private const int _keySize = 256;
        private const int _macSize = 128;
        private const int _nonceSize = 128;
        private static readonly SecureRandom _random = new SecureRandom();

        public static byte[] Decrypt(byte[] encryptedMessage, byte[] key)
        {
            if (encryptedMessage == null || encryptedMessage.Length == 0)
            {
                throw new ArgumentNullException("encryptedMessage");
            }

            using var cipherStream = new MemoryStream(encryptedMessage);
            using var cipherReader = new BinaryReader(cipherStream);

            var nonce = cipherReader.ReadBytes(_nonceSize / 8);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), _macSize, nonce);
            cipher.Init(false, parameters);

            var cipherText = cipherReader.ReadBytes(encryptedMessage.Length - nonce.Length);
            var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];

            var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
            cipher.DoFinal(plainText, len);

            return plainText;
        }

        public static byte[] Encrypt(byte[] messageToEncrypt, byte[] key)
        {
            var nonce = new byte[_nonceSize / 8];
            _random.NextBytes(nonce, 0, nonce.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), _macSize, nonce);
            cipher.Init(true, parameters);

            //Generate Cipher Text With Auth Tag
            var cipherText = new byte[cipher.GetOutputSize(messageToEncrypt.Length)];
            var len = cipher.ProcessBytes(messageToEncrypt, 0, messageToEncrypt.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);

            //Assemble Message
            using (var combinedStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(combinedStream))
                {
                    //Prepend Nonce
                    binaryWriter.Write(nonce);
                    //Write Cipher Text
                    binaryWriter.Write(cipherText);
                }
                return combinedStream.ToArray();
            }
        }
    }
}