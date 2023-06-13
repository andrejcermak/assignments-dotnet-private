using System;
using System.Security.Cryptography;
using System.Text;

namespace Datamole.InterviewAssignments.IdentityService.Helpers
{
    /// <summary>
    /// Password hasher implementation from
    /// https://code-maze.com/csharp-hashing-salting-passwords-best-practices/
    /// </summary>
    public class PasswordHasher
    {
        const int keySize = 64;
        const int iterations = 350000;
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
        
        public PasswordObject HashPassword(string password)
        {
            byte[] salt = {};
            salt = RandomNumberGenerator.GetBytes(keySize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                iterations,
                hashAlgorithm,
                keySize);
            return new PasswordObject() { HashedPassword = Convert.ToHexString(hash), Salt = salt };
        }
        
        public bool VerifyPassword(string password, string hash, byte[] salt)
        {
            var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, keySize);
            return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
        }
    }

    public class PasswordObject
    {
        public string HashedPassword { get; set; }
        public byte[] Salt { get; set; }
    }
}
