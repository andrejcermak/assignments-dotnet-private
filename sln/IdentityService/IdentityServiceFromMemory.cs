using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityServiceFromMemory : IdentityService
    {
        internal IdentityServiceFromMemory(
            PasswordHasher passwordHasher,
            StringEncryptionService encryptionService,
            Dictionary<string, UserData> database,
            IEnumerable<string> users,
            IEnumerable<string> passwords) : base(passwordHasher, encryptionService, database)
        {
            CheckCorrectInput(users, passwords);
            foreach (var (userName, password) in users.Zip(passwords))
            {
                var userNameLowerCaseEncrypted =
                    Convert.ToBase64String(encryptionService.EncryptAsync(userName.ToLower()).Result);
                var originalUserNameEncrypted =
                    Convert.ToBase64String(encryptionService.EncryptAsync(userName).Result);
                database.Add(userNameLowerCaseEncrypted,
                    new UserData(
                        userNameLowerCaseEncrypted,
                        passwordHasher.HashPassword(password),
                        new Dictionary<string, string>(),
                        originalUserNameEncrypted));
            }
        }
        private static void CheckCorrectInput(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            if (users.Count() != passwords.Count())
            {
                throw new Exception("Invalid input");
            }
        }
    }
}
