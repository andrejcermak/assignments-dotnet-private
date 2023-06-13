using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Datamole.InterviewAssignments.IdentityService.Models;

using System.Text.Json;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityService : IIdentityService
    {

        internal Dictionary<string, UserData> Database { get; set; }
        internal PasswordHasher PasswordHasher { get; set; }
        
        internal StringEncryptionService EncryptionService { get; set; }

        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            var encryptedUserName = Convert.ToBase64String(EncryptionService.EncryptAsync(userName.ToLower(), "passphrase").Result);
            var encryptedOriginalUserName =
                Convert.ToBase64String(EncryptionService.EncryptAsync(userName, "passphrase").Result);
            if (!Database.ContainsKey(encryptedUserName))
            {
                Database.Add(Convert.ToBase64String(EncryptionService.EncryptAsync(
                    userName.ToLower(), "passphrase").Result), 
                    new UserData(
                        encryptedUserName,
                        PasswordHasher.HashPassword(password),
                        properties?? new Dictionary<string, string>(),
                        encryptedOriginalUserName));
                
                return RegistrationResult.Successful();
            }

            return RegistrationResult.Failed(RegistrationError.UserAlreadyExists);
        }

        public AuthenticationResult Authenticate(string userName, string password)
        {
            var userData = Database.GetValueOrDefault(Convert.ToBase64String(EncryptionService.EncryptAsync(
                userName.ToLower(), "passphrase").Result));
            if (userData is null)
            {
                return AuthenticationResult.Failed(AuthenticationError.UserNotFound);
            }

            if (!PasswordHasher.VerifyPassword(password, userData.Password.HashedPassword, userData.Password.Salt))
            {
                return AuthenticationResult.Failed(AuthenticationError.InvalidPassword);
            }

            return AuthenticationResult.Successful(EncryptionService.DecryptAsync(Convert.FromBase64String(userData.EncryptedOriginalName), "passphrase").Result, userData.Properties);
        }

        public void SaveToJson(string pathToJsonFile, bool overwrite = false)
        {
            var result = JsonSerializer.Serialize(Database.Values, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase}
            );
            Console.WriteLine(pathToJsonFile);
            if (!overwrite && File.Exists(pathToJsonFile))
            {
                throw new ArgumentException();
            }

            File.WriteAllText(pathToJsonFile, result);
        }

        public class UserData
        {
            public string EncryptedName { get; set; }
            public string EncryptedOriginalName { get; set; }
            
            public IDictionary<string, string> Properties { get; set; }
            public PasswordObject Password { get; set; }

            public UserData(string encryptedName, PasswordObject password, IDictionary<string, string>? properties, string encryptedOriginalName)
            {
                EncryptedName = encryptedName;
                Password = password;
                Properties = properties;
                EncryptedOriginalName = encryptedOriginalName;
            }
        }
    }
}
