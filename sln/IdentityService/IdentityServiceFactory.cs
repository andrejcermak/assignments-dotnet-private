using System.Collections.Generic;

using Datamole.InterviewAssignments.IdentityService.Helpers;
using Datamole.InterviewAssignments.IdentityService.Models;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile) =>
            new IdentityServiceFromFile(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, UserData>(),
                pathToJsonFile);

        public static IIdentityService CreateFromMemory(IEnumerable<string> users,
            IEnumerable<string> passwords) =>
            new IdentityServiceFromMemory(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, UserData>(),
                users,
                passwords);
    }
}
