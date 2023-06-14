using System.Collections.Generic;

using Datamole.InterviewAssignments.IdentityService.Helpers;

namespace Datamole.InterviewAssignments.IdentityService.Models
{
    public class UserData
    {
        public string EncryptedName { get; }
        public string EncryptedOriginalName { get; }
            
        public IDictionary<string, string> Properties { get; }
        public PasswordObject Password { get; }

        public UserData(string encryptedName, PasswordObject password, IDictionary<string, string>? properties, string encryptedOriginalName)
        {
            EncryptedName = encryptedName;
            Password = password;
            Properties = properties;
            EncryptedOriginalName = encryptedOriginalName;
        }
    }
}
