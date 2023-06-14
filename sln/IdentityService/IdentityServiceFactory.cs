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
            CheckFileConsistency(pathToJsonFile);
            return InitializeIdentityService().FillDatabaseFromFile(pathToJsonFile);
        }


        public static async Task<IIdentityService> CreateFromMemory(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            CheckCorrectInput(users, passwords);
            return await InitializeIdentityService().FillDatabaseFromMemoryAsync(users, passwords);
        }

        private static void CheckCorrectInput(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            if (users.Count() != passwords.Count())
            {
                throw new Exception("Invalid input");
            }
        }

        private static void CheckFileConsistency(string pathToJsonFile)
        {
            using var stream = File.OpenRead(pathToJsonFile);
            var hash = SHA256.Create().ComputeHash(stream);
            var stringHash = Convert.ToBase64String(hash);
            if (stringHash != File.ReadAllText(pathToJsonFile + ".hash"))
            {
                throw new Exception("CONSISTENCY ISSUE. POSSIBLE SENSITIVE DATA LEAK.");
            }
        }

        private static IdentityService InitializeIdentityService() => new (
            new PasswordHasher(), 
            new StringEncryptionService("pass"), 
            new Dictionary<string, IdentityService.UserData>());
    }
}
