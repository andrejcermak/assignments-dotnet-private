using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

using Datamole.InterviewAssignments.IdentityService.Models;

using System.Text.Json;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    /// <summary>
    /// Abstract identity service handling all the identity logic
    /// </summary>
    
    public abstract class AbstractIdentityService : IIdentityService
    {
        private Dictionary<string, UserData> Database { get; }
        private PasswordHasher PasswordHasher { get; }

        private StringEncryptionService EncryptionService { get; }

        internal AbstractIdentityService(PasswordHasher passwordHasher, StringEncryptionService encryptionService, Dictionary<string, UserData> database)
        {
            PasswordHasher = passwordHasher;
            EncryptionService = encryptionService;
            Database = database;
        }

        internal string CalculateFileHash(Stream inputStream)
        {
            var hash = SHA256.Create().ComputeHash(inputStream);
            return Convert.ToBase64String(hash);
        }

        /// <inheritdoc/>
        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            var encryptedUserName = EncryptionService.Encrypt(userName.ToLower());
            var encryptedOriginalUserName =EncryptionService.Encrypt(userName);
            if (!Database.ContainsKey(encryptedUserName))
            {
                Database.Add(encryptedUserName, 
                    new UserData(
                        encryptedUserName,
                        PasswordHasher.HashPassword(password),
                        properties?? new Dictionary<string, string>(),
                        encryptedOriginalUserName));
                
                return RegistrationResult.Successful();
            }

            return RegistrationResult.Failed(RegistrationError.UserAlreadyExists);
        }

        /// <inheritdoc/>
        public AuthenticationResult Authenticate(string userName, string password)
        {
            var userData = Database.GetValueOrDefault(EncryptionService.Encrypt(userName.ToLower()));
            if (userData is null)
            {
                return AuthenticationResult.Failed(AuthenticationError.UserNotFound);
            }

            if (!PasswordHasher.VerifyPassword(password, userData.Password.HashedPassword, userData.Password.Salt))
            {
                return AuthenticationResult.Failed(AuthenticationError.InvalidPassword);
            }

            return AuthenticationResult.Successful(EncryptionService.Decrypt(userData.EncryptedOriginalName), userData.Properties);
        }
        
        /// <inheritdoc/>
        public void SaveToJson(string pathToJsonFile, bool overwrite = false)
        {
            var result = JsonSerializer.Serialize(Database.Values, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase}
            );
            var stringHash = CalculateFileHash(new MemoryStream(Encoding.UTF8.GetBytes(result)));
            File.WriteAllText(pathToJsonFile + ".hash", stringHash);

            if (!overwrite && File.Exists(pathToJsonFile))
            {
                throw new ArgumentException();
            }

            File.WriteAllText(pathToJsonFile, result);
        }
    }
}
