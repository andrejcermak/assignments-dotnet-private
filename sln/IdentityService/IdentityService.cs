using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using Datamole.InterviewAssignments.IdentityService.Models;

using System.Text.Json;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityService : IIdentityService
    {

        private Dictionary<string, UserData> _database = new();

        internal IdentityService(Dictionary<string, UserData> database)
        {
            _database = database;
        }
        
        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            if (!_database.ContainsKey(userName.ToLower()))
            {
                _database.Add(userName.ToLower(), new UserData(userName, password, properties?? new Dictionary<string, string>()));
                return RegistrationResult.Successful();
            }

            return RegistrationResult.Failed(RegistrationError.UserAlreadyExists);
        }

        public AuthenticationResult Authenticate(string userName, string password)
        {
            var userData = _database.GetValueOrDefault(userName.ToLower());
            if (userData is null)
            {
                return AuthenticationResult.Failed(AuthenticationError.UserNotFound);
            }

            if (userData.Password != password)
            {
                return AuthenticationResult.Failed(AuthenticationError.InvalidPassword);
            }

            return AuthenticationResult.Successful(userData.Name, userData.Properties);
        }

        public void SaveToJson(string pathToJsonFile, bool overwrite = false) => throw new System.NotImplementedException();
    }
}
