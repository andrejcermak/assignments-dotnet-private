using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile)
        {
            var fileContents = File.ReadAllText(pathToJsonFile);
            Console.WriteLine(fileContents);
            var database = JsonSerializer.Deserialize<Dictionary<string, IdentityService.UserData>>(fileContents);
            return new IdentityService(database);
        }

        public static IIdentityService CreateFromMemory(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            if (users.Count() != passwords.Count())
            {
                throw new Exception("Invalid input");
            }

            var database = new Dictionary<string, IdentityService.UserData>();
            foreach (var (userName, password) in users.Zip(passwords))
            {
                database.Add(userName.ToLower(),
                    new IdentityService.UserData(userName, password, new Dictionary<string, string>()));
                Console.WriteLine(
                    JsonSerializer.Serialize(new IdentityService.UserData(userName, password,
                        new Dictionary<string, string>())));
            }
            return new IdentityService(database);
        }
    }
}
