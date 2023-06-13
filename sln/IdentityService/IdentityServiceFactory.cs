using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile)
        {
            var fileContents = File.ReadAllText(pathToJsonFile);
            var database = JsonSerializer.Deserialize<Dictionary<string, IdentityService.UserData>>(fileContents);
            var service = new IdentityService { PasswordHasher = new PasswordHasher(), Database = database };
            return service;
        }

        public static IIdentityService CreateFromMemory(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            if (users.Count() != passwords.Count())
            {
                throw new Exception("Invalid input");
            }

            var service = new IdentityService { PasswordHasher = new PasswordHasher() };
            var database = new Dictionary<string, IdentityService.UserData>();
            foreach (var (userName, password) in users.Zip(passwords))
            {
                database.Add(userName.ToLower(),
                    new IdentityService.UserData(userName, service.PasswordHasher.HashPassword(password), new Dictionary<string, string>()));
            }

            service.Database = database;
            return service;
        }
    }
}
