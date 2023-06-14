using System.Collections.Generic;

using Datamole.InterviewAssignments.IdentityService.Models;

namespace Datamole.InterviewAssignments.IdentityService
{
    public interface IIdentityService
    {
        /// <summary>
        /// Registers a user by storing their encrypted username, hashed password, and optional properties in the
        /// database. Returns a <see cref="RegistrationResult"/> indicating success or failure, with
        /// <see cref="RegistrationError"/>
        /// </summary>
        /// <param name="userName">Case insensitive user name</param>
        /// <param name="password">Password</param>
        /// <param name="properties">Dictionary with additional properties </param>
        /// <returns><see cref="RegistrationResult"/></returns>
        RegistrationResult Register(string userName, string password, IDictionary<string, string>? properties = null);

        /// <summary>
        /// Authenticates a user by verifying the provided password against the stored hashed password. Returns an
        /// <see cref="AuthenticationResult"/> indicating success with the decrypted original username and
        /// associated properties, or failure with <see cref="AuthenticationError"/>
        /// </summary>
        /// <param name="userName">Case insensitive user name</param>
        /// <param name="password">Password</param>
        /// <returns><see cref="AuthenticationResult"/></returns>
        AuthenticationResult Authenticate(string userName, string password);
        
        /// <summary>
        /// Serializes the values of the database to JSON format and saves them to a file specified by the
        /// pathToJsonFile parameter. Aslo calculates the hash of the serialized data and saves it to a separate file
        /// with the ".hash" extension. If the overwrite parameter is set to false and the file already exists, an
        /// ArgumentException is thrown.
        /// </summary>
        /// <param name="pathToJsonFile"></param>
        /// <param name="overwrite"></param>
        void SaveToJson(string pathToJsonFile, bool overwrite = false);
    }
}
