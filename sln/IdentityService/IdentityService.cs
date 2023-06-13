using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

using Datamole.InterviewAssignments.IdentityService.Models;

using System.Text.Json;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityService : IIdentityService
    {

        internal Dictionary<string, UserData> Database { get; set; }
        internal PasswordHasher PasswordHasher { get; set; }

        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            if (!Database.ContainsKey(userName.ToLower()))
            {
                Database.Add(userName.ToLower(), new UserData(userName, PasswordHasher.HashPassword(password), properties?? new Dictionary<string, string>()));
                return RegistrationResult.Successful();
            }

            return RegistrationResult.Failed(RegistrationError.UserAlreadyExists);
        }

        public AuthenticationResult Authenticate(string userName, string password)
        {
            var userData = Database.GetValueOrDefault(userName.ToLower());
            if (userData is null)
            {
                return AuthenticationResult.Failed(AuthenticationError.UserNotFound);
            }

            if (!PasswordHasher.VerifyPassword(password, userData.Password.HashedPassword, userData.Password.Salt))
            {
                return AuthenticationResult.Failed(AuthenticationError.InvalidPassword);
            }

            return AuthenticationResult.Successful(userData.Name, userData.Properties);
        }

        public void SaveToJson(string pathToJsonFile, bool overwrite = false)
        {
            var result = JsonSerializer.Serialize(Database);
            Console.WriteLine(pathToJsonFile);
            if (!overwrite && File.Exists(pathToJsonFile))
            {
                throw new ArgumentException();
            }

            File.WriteAllText(pathToJsonFile, result);
        }

        public class UserData
        {
            public string Name { get; set; }
            public IDictionary<string, string> Properties { get; set; }
            public PasswordObject Password { get; set; }

            public UserData(string name, PasswordObject password, IDictionary<string, string>? properties)
            {
                Name = name;
                Password = password;
                Properties = properties;
            }
        }
    }
}
