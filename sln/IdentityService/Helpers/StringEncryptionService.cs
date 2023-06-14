using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Datamole.InterviewAssignments.IdentityService.Helpers
{
    /// <summary>
    /// Password hasher implementation from
    /// https://code-maze.com/csharp-string-encryption-decryption/
    /// </summary>
    public class StringEncryptionService
    {
        private byte[] IV =
        {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16
        };

        public StringEncryptionService(string passphrase)
        {
            Passphrase = passphrase;
        }

        private string Passphrase { get; set; }

        private byte[] DeriveKeyFromPassword(string password)
        {
            var emptySalt = Array.Empty<byte>();
            const int iterations = 1000;
            const int desiredKeyLength = 16; // 16 bytes equal 128 bits.
            var hashMethod = HashAlgorithmName.SHA384;
            return Rfc2898DeriveBytes.Pbkdf2(
                Encoding.Unicode.GetBytes(password),
                emptySalt,
                iterations,
                hashMethod,
                desiredKeyLength);
        }
        
        private async Task<byte[]> EncryptAsync(string clearText)
        {
            using Aes aes = Aes.Create();
            aes.Key = DeriveKeyFromPassword(Passphrase);
            aes.IV = IV;
            using MemoryStream output = new();
            using CryptoStream cryptoStream = new(output, aes.CreateEncryptor(), CryptoStreamMode.Write);
            await cryptoStream.WriteAsync(Encoding.Unicode.GetBytes(clearText));
            await cryptoStream.FlushFinalBlockAsync();
            return output.ToArray();
        }
        
        private async Task<string> DecryptAsync(byte[] encrypted)
        {
            using Aes aes = Aes.Create();
            aes.Key = DeriveKeyFromPassword(Passphrase);
            aes.IV = IV;
            using MemoryStream input = new(encrypted);
            using CryptoStream cryptoStream = new(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using MemoryStream output = new();
            await cryptoStream.CopyToAsync(output);
            return Encoding.Unicode.GetString(output.ToArray());
        }

        public string Encrypt(string clearText) => Convert.ToBase64String(EncryptAsync(clearText).Result);
        
        public string Decrypt(string encrypted) => DecryptAsync(Convert.FromBase64String(encrypted)).Result;

    }
}
