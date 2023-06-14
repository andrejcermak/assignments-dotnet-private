using System;
using System.Collections.Generic;
using System.Linq;

using Datamole.InterviewAssignments.IdentityService.Helpers;
using Datamole.InterviewAssignments.IdentityService.Models;

namespace Datamole.InterviewAssignments.IdentityService
{
    /// <summary>
    /// Concrete implementation of identity service using data from memory
    /// </summary>
    public class IdentityServiceFromMemory : AbstractIdentityService
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
                var userNameLowerCaseEncrypted =encryptionService.Encrypt(userName.ToLower());
                var originalUserNameEncrypted = encryptionService.Encrypt(userName);
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
