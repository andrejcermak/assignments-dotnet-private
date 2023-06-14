using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Datamole.InterviewAssignments.IdentityService.Models;

using System.Text.Json;
using System.Threading.Tasks;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityService : IIdentityService
    {
        private Dictionary<string, UserData> Database { get; }
        private PasswordHasher PasswordHasher { get; }

        private StringEncryptionService EncryptionService { get; }

        internal IdentityService(PasswordHasher passwordHasher, StringEncryptionService encryptionService, Dictionary<string, UserData> database)
        {
            PasswordHasher = passwordHasher;
            EncryptionService = encryptionService;
            Database = database;
        }

        internal IdentityService FillDatabaseFromFile(string pathToJsonFile)
        {
            var fileContents = File.ReadAllText(pathToJsonFile);
            var userData = JsonSerializer.Deserialize<List<UserData>>(fileContents, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                }
            );
            userData.ForEach(user => Database.Add(user.EncryptedName, user));
            return this;
        }
        internal async Task<IdentityService> FillDatabaseFromMemoryAsync(
            IEnumerable<string> users,
            IEnumerable<string> passwords)
        {
            foreach (var (userName, password) in users.Zip(passwords))
            {
                var userNameLowerCaseEncrypted =
                    Convert.ToBase64String(await EncryptionService.EncryptAsync(userName.ToLower()));
                var originalUserNameEncrypted =
                    Convert.ToBase64String(await EncryptionService.EncryptAsync(userName));
                Database.Add(userNameLowerCaseEncrypted,
                    new UserData(
                        userNameLowerCaseEncrypted,
                        PasswordHasher.HashPassword(password),
                        new Dictionary<string, string>(),
                        originalUserNameEncrypted));
            }
            return this;
        }
        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            var encryptedUserName = Convert.ToBase64String(EncryptionService.EncryptAsync(userName.ToLower()).Result);
            var encryptedOriginalUserName =
                Convert.ToBase64String(EncryptionService.EncryptAsync(userName).Result);
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

        public AuthenticationResult Authenticate(string userName, string password)
        {
            var userData = Database.GetValueOrDefault(Convert.ToBase64String(EncryptionService.EncryptAsync(
                userName.ToLower()).Result));
            if (userData is null)
            {
                return AuthenticationResult.Failed(AuthenticationError.UserNotFound);
            }

            if (!PasswordHasher.VerifyPassword(password, userData.Password.HashedPassword, userData.Password.Salt))
            {
                return AuthenticationResult.Failed(AuthenticationError.InvalidPassword);
            }

            return AuthenticationResult.Successful(EncryptionService.DecryptAsync(Convert.FromBase64String(userData.EncryptedOriginalName)).Result, userData.Properties);
        }

        public void SaveToJson(string pathToJsonFile, bool overwrite = false)
        {
            var result = JsonSerializer.Serialize(Database.Values, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase}
            );
            var hash = SHA256.Create().ComputeHash(new MemoryStream(Encoding.UTF8.GetBytes(result)));
            var stringHash = Convert.ToBase64String(hash);
            File.WriteAllText(pathToJsonFile + ".hash", stringHash);

            Console.WriteLine("Writing to : " + pathToJsonFile);
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
