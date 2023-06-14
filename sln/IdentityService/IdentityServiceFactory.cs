using System.Collections.Generic;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile) =>
            new AbstractIdentityServiceFromFile(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, AbstractIdentityService.UserData>(),
                pathToJsonFile);

        public static IIdentityService CreateFromMemory(IEnumerable<string> users,
            IEnumerable<string> passwords) =>
            new AbstractIdentityServiceFromMemory(
                new PasswordHasher(),
                new StringEncryptionService(""),
                new Dictionary<string, AbstractIdentityService.UserData>(),
                users,
                passwords);
    }
}
