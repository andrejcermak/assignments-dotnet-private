using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile)
        {
            var stringHash = string.Empty;
            using (var stream = File.OpenRead(pathToJsonFile))
            {
                byte[] hash = SHA256.Create().ComputeHash(stream);
                stringHash = Convert.ToBase64String(hash);
                if (stringHash != File.ReadAllText(pathToJsonFile + ".hash"))
                {
                    throw new Exception("CONSISTENCY ISSUE. POSSIBLE SENSITIVE DATA LEAK.");
                }
            }
            
            var fileContents = File.ReadAllText(pathToJsonFile);
            var encryptionService = new StringEncryptionService();
            var userData = JsonSerializer.Deserialize<List<IdentityService.UserData>>(fileContents, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase}
            );
            var database = userData.ToDictionary(user => user.EncryptedName);
            var service = new IdentityService { PasswordHasher = new PasswordHasher(), Database = database, EncryptionService = encryptionService};
            return service;
        }

        public static async Task<IIdentityService> CreateFromMemory(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            if (users.Count() != passwords.Count())
            {
                throw new Exception("Invalid input");
            }

            var service = new IdentityService { PasswordHasher = new PasswordHasher() };
            var encryptionService = new StringEncryptionService();
            var database = new Dictionary<string, IdentityService.UserData>();
            foreach (var (userName, password) in users.Zip(passwords))
            {
                var userNameLowerCaseEncrypted = Convert.ToBase64String(await encryptionService.EncryptAsync(userName.ToLower(), "passphrase"));
                var originalUserNameEncrypted = Convert.ToBase64String(await encryptionService.EncryptAsync(userName, "passphrase"));
                database.Add(
                    userNameLowerCaseEncrypted,
                    new IdentityService.UserData(
                        userNameLowerCaseEncrypted, 
                        service.PasswordHasher.HashPassword(password),
                        new Dictionary<string, string>(),
                        originalUserNameEncrypted));
            }

            service.EncryptionService = encryptionService;
            service.Database = database;
            return service;
        }
    }
}
