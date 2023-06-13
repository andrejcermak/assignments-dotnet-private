using System.Collections.Generic;
using System.Linq;

using Datamole.InterviewAssignments.IdentityService.Models;

namespace Datamole.InterviewAssignments.IdentityService
{
    public class IdentityService: IIdentityService
    {
        private List<string> _users;
        private List<string> _passwords;
        
        
        public IdentityService(IEnumerable<string> users, IEnumerable<string> passwords)
        {
            _users = users.ToList();
            _passwords = passwords.ToList();
        }

        public RegistrationResult Register(string userName, string password,
            IDictionary<string, string>? properties = null)
        {
            if (_users.FirstOrDefault(user => user.ToLower().Equals(userName.ToLower())) is null)
            {
                _users.Add(userName);
                _passwords.Add(password);
                return RegistrationResult.Successful();
            }
            return RegistrationResult.Failed(RegistrationError.UserAlreadyExists);
        }

        public AuthenticationResult Authenticate(string userName, string password) => throw new System.NotImplementedException();

        public void SaveToJson(string pathToJsonFile, bool overwrite = false) => throw new System.NotImplementedException();
    }
}
