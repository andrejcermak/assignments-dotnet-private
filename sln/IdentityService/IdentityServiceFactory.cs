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
        public static IIdentityService CreateFromJson(string pathToJsonFile) =>
            new IdentityServiceFromFile(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, IdentityService.UserData>(),
                pathToJsonFile);

        public static async Task<IIdentityService> CreateFromMemory(IEnumerable<string> users,
            IEnumerable<string> passwords) =>
            new IdentityServiceFromMemory(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, IdentityService.UserData>(),
                users,
                passwords);
    }
}
