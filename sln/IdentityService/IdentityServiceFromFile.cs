﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

using Datamole.InterviewAssignments.IdentityService.Helpers;
using Datamole.InterviewAssignments.IdentityService.Models;

namespace Datamole.InterviewAssignments.IdentityService
{
    /// <summary>
    /// Concrete implementation of identity service using data from json file
    /// </summary>
    public class IdentityServiceFromFile : AbstractIdentityService
    {
        internal IdentityServiceFromFile(
            PasswordHasher passwordHasher, 
            StringEncryptionService encryptionService, 
            Dictionary<string, UserData> database,
            string pathToJsonFile) : base(passwordHasher, encryptionService, database)
        {
            CheckFileConsistency(pathToJsonFile);
            var fileContents = File.ReadAllText(pathToJsonFile);
            var userData = JsonSerializer.Deserialize<List<UserData>>(fileContents, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                }
            );
            userData.ForEach(user => database.Add(user.EncryptedName, user));
        }

        private void CheckFileConsistency(string pathToJsonFile)
        {
            using var stream = File.OpenRead(pathToJsonFile);
            var stringHash = this.CalculateFileHash(stream);
            if (stringHash != File.ReadAllText(pathToJsonFile + ".hash"))
            {
                throw new Exception("CONSISTENCY ISSUE. POSSIBLE SENSITIVE DATA LEAK.");
            }
        }
    }
}
