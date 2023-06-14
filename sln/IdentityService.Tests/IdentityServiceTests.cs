using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Datamole.InterviewAssignments.IdentityService.Models;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Datamole.InterviewAssignments.IdentityService.Tests
{
    [TestClass]
    public class IdentityServiceTests
    {
        [TestMethod]
        [DataRow("jsmith", "jane123.")]
        [DataRow("jSmith", "jane123.")]
        public async Task AuthenticationTest_SuccessfulAuthentication(string userName, string password)
        {
            // Arrange
            var service =
                IdentityServiceFactory.CreateFromMemory(new List<string> { "jsmith" }, new List<string> { "jane123." });

            // Act
            var result =  service.Authenticate(userName, password);

            // Assert
            Assert.IsTrue(result.IsSuccessful);
            Assert.IsNull(result.Error);
            Assert.IsFalse(result.Properties?.Any());
        }



        [TestMethod]
        [DataRow("jsmitch", "jane123.",  AuthenticationError.UserNotFound, null, null)]
        [DataRow("jsmith", "jane123",  AuthenticationError.InvalidPassword, null, null)]
        [DataRow("jSmith", "Jane123.",  AuthenticationError.InvalidPassword, null, null)]
        public async Task AuthenticationTest_FailedAuthentication(string userName, string password, AuthenticationError error, IDictionary<string, string> properties, string originalUserName)
        {
            // Arrange
            var service = IdentityServiceFactory.CreateFromMemory(new List<string> { "jsmith" }, new List<string> { "jane123." });

            // Act
            var result = service.Authenticate(userName, password);
            
            // Assert
            Assert.IsFalse(result.IsSuccessful);
            Assert.AreEqual(error, result.Error);
            if (error is AuthenticationError.UserNotFound)
            {
                Assert.AreEqual(result.Properties, properties);
                Assert.AreEqual(result.OriginalUserName, originalUserName);
            }
        }

        [TestMethod]
        public async Task RegistrationTest_RegistrationOfNewUserSucceeds()
        {
            // Arrange
            var service = IdentityServiceFactory.CreateFromMemory(new List<string> { "janeSmith" }, new List<string> { "john123." });
            var customProperties = new Dictionary<string, string>
            {
                {"Prop1", "Val1"},
                {"Prop2", "Val2"}
            };

            // Act
            var result2 = service.Register("jSmith", "jane123.", customProperties);
            
            // Assert
            Assert.IsTrue(result2.IsSuccessful);
            Assert.IsNull(result2.Error);
            
        }
        
        [TestMethod]
        public async Task RegistrationTest_RegistrationOfExistingUserFails()
        {
            // Arrange
            var service = IdentityServiceFactory.CreateFromMemory(new List<string> { "janeSmith" }, new List<string> { "john123." });

            // Act
            var result6 = service.Register("JaneSmith", "john123.");
            
            // Assert
            Assert.IsFalse(result6.IsSuccessful);
            Assert.AreEqual(RegistrationError.UserAlreadyExists, result6.Error);
            
        }
        
        [TestMethod]
        public async Task RegistrationTest_RegistrationAuthenticationFlowTest()
        {
            // Arrange

            var service = IdentityServiceFactory.CreateFromMemory(ImmutableList<string>.Empty, ImmutableList<string>.Empty);

            var customProperties = new Dictionary<string, string>
            {
                {"Prop1", "Val1"},
                {"Prop2", "Val2"}
            };

            // Act

            var result2 = service.Register("jSmith", "jane123.", customProperties);
            var result3 = service.Authenticate("jsmith", "jane123.");
            
            // Assert
            Assert.IsTrue(result2.IsSuccessful);
            Assert.IsNull(result2.Error);


            Assert.IsTrue(result3.IsSuccessful);
            Assert.IsNull(result3.Error);
            Assert.AreEqual("jSmith", result3.OriginalUserName);
            Assert.AreEqual(2, result3.Properties?.Count);
            Assert.AreEqual(customProperties["Prop1"], result3.Properties?["Prop1"]);
            Assert.AreEqual(customProperties["Prop2"], result3.Properties?["Prop2"]);
        }

        [TestMethod]
        public void ReadingFromMemory_ThrowsExceptionWhenInvalidInput()
        {
            // Arrange
            var input = (new List<string> { "janeSmith" , "anotherUserWithouPassword"}, new List<string> { "john123." });

            // Act
            var action = new Func<IIdentityService>(() => IdentityServiceFactory.CreateFromMemory(input.Item1, input.Item2));

            // Assert
            Assert.ThrowsException<Exception>(action);
        }
        
        [TestMethod]
        public void SavingToFileTest_SucceedsWhenConsistentData()
        {
            // Arrange
            var filePath = $"{Guid.NewGuid()}.json";
            var service = IdentityServiceFactory.CreateFromMemory(new List<string> { "jsmith" }, new List<string> { "jane123." });
            service.SaveToJson(filePath);
            
            // Act
            var service2 = IdentityServiceFactory.CreateFromJson(filePath);
            
            // Assert
            Assert.IsInstanceOfType(service2, typeof(IIdentityService));
            File.Delete(filePath);
        }
        
        [TestMethod]
        public void SavingToFileTest_ThrowsExceptionWhenInconsistentData()
        {
            // Arrange
            var filePath = $"{Guid.NewGuid()}.json";
            var service = IdentityServiceFactory.CreateFromMemory(new List<string> { "jsmith" }, new List<string> { "jane123." });
            service.SaveToJson(filePath);
            
            // Act
            File.WriteAllText(filePath,"Overwritten data");

            // Assert
            Assert.ThrowsException<Exception>(() => IdentityServiceFactory.CreateFromJson(filePath));
            File.Delete(filePath);
        }

        [TestMethod]
        public void SavingToFileTest()
        {
            // Arrange

            var filePath = $"{Guid.NewGuid()}.json";
            var customProperties = new Dictionary<string, string>
            {
                {"Prop1", "Val1"},
                {"Prop2", "Val2"}
            };

            var service1 = IdentityServiceFactory.CreateFromMemory(new List<string> { "jsmith" }, new List<string> { "jane123." });

            // Act

            var result1 = service1.Authenticate("JaneSmith", "john123.");
            var result2 = service1.Register("JaneSmith", "john123.");
            var result3 = service1.Register("JaneSmithX", "john123.X", customProperties);

            service1.SaveToJson(filePath);

            var fileContents = File.ReadAllText(filePath);

            var service2 = IdentityServiceFactory.CreateFromJson(filePath);

            var result4 = service2.Authenticate("jsmiTh", "jane123.");
            var result5 = service2.Authenticate("janESmith", "john123.");
            var result6 = service2.Authenticate("janeSmithX", "john123.X");

            // Assert

            Assert.IsFalse(result1.IsSuccessful);
            Assert.IsTrue(result2.IsSuccessful);
            Assert.IsTrue(result3.IsSuccessful);

            Assert.IsTrue(result4.IsSuccessful);
            Assert.IsTrue(result5.IsSuccessful);
            Assert.AreEqual("JaneSmith", result5.OriginalUserName);
            Assert.IsFalse(result5.Properties?.Any());

            Assert.IsTrue(result6.IsSuccessful);
            Assert.AreEqual("JaneSmithX", result6.OriginalUserName);
            Assert.AreEqual(2, result6.Properties?.Count);
            Assert.AreEqual(customProperties["Prop1"], result6.Properties?["Prop1"]);
            Assert.AreEqual(customProperties["Prop2"], result6.Properties?["Prop2"]);

            try
            {
                var fileJson = JToken.Parse(fileContents);

                AssertCamelCaseJson(fileJson);
            }
            catch (JsonException ex)
            {
                Assert.Fail($"Invalid JSON format: {ex.Message}");
            }


            Assert.ThrowsException<ArgumentException>(() => service1.SaveToJson(filePath));

            // Cleanup in case of success

            File.Delete(filePath);
        }

        private void AssertCamelCaseJson(JToken token)
        {
            if (token is JObject obj)
            {
                Console.WriteLine(token);
                Assert.IsTrue(obj.Properties().Select(p => p.Name.First()).All(char.IsLower), "Invalid format of property name.");
            }
            else if (token is JArray array)
            {
                foreach (var arrayObject in array)
                {
                    AssertCamelCaseJson(arrayObject);
                }
            }
        }
    }
}
