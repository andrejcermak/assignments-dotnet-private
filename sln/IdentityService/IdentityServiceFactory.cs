using System;
using System.Collections.Generic;

namespace Datamole.InterviewAssignments.IdentityService
{
    public static class IdentityServiceFactory
    {
        public static IIdentityService CreateFromJson(string pathToJsonFile)
        {
            // TODO: Implement

            throw new NotImplementedException();
        }

        public static IIdentityService CreateFromMemory(IEnumerable<string> users, IEnumerable<string> passwords) => new IdentityService(users, passwords);
    }
}
