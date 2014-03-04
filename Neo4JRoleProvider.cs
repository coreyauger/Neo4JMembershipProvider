using System;
using System.Linq;
using System.Configuration;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Data;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Web.Configuration;
using System.Web.Security;
using System.Collections.Generic;

using WebMatrix.WebData;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Neo4jClient;

using Nextwave.Neo4J.Membership.Data;

namespace Nextwave.Neo4J.Membership
{
    public class Neo4JRolesProvider : RoleProvider
    {
        private string applicationName;
        private GraphClient _neoClient = null;
        private string connectionString;
        public override string ApplicationName
        {
            get
            {
                return applicationName;
            }
            set
            {
                applicationName = value;
            }
        }

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (name == null || name.Length == 0)
            {
                name = "Neo4JRoleProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Neo4J Role Provider");
            }

            //Initialize the abstract base class.
            base.Initialize(name, config);

            applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);

            ConnectionStringSettings ConnectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];



            if (ConnectionStringSettings == null || ConnectionStringSettings.ConnectionString.Trim() == "")
            {
                throw new ProviderException("Connection string cannot be blank.");
            }

            connectionString = ConnectionStringSettings.ConnectionString;

            // CA - init our connection client
            _neoClient = new GraphClient(new Uri(connectionString));
            _neoClient.Connect();

        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                foreach (string username in usernames)
                {
                    Node<User> u = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == applicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                    if (u != null)
                    {
                        List<Node<Role>> roles = _neoClient.Cypher
                                                .Match("(n:Role)")
                                                .Return<Node<Role>>("n").Results.ToList();
                        foreach (var r in roles)
                        {
                            foreach (string roleName in roleNames)
                            {
                                if (r.Data.RoleName == roleName)
                                {
                                    _neoClient.Cypher
                                        .Match("(user:User)", "(role:Role)")
                                        .Where((User user) => user.Username == username)
                                        .AndWhere((Role role) => role.RoleName == roleName)
                                        .CreateUnique("user-[r:MEMBER_OF]->role")
                                        .Set("r.CreatedOn = {createdOn}")
                                        .WithParam("createdOn", DateTime.UtcNow)
                                        .ExecuteWithoutResults();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {

            }
        }

        public override void CreateRole(string roleName)
        {
            Role role = new Role();
            role.RoleName = roleName;

            _neoClient.Cypher
            .Merge("(role:Role {RoleName: {roleName} })")
            .OnCreate()
            .Set("role = {newRole}")
            .WithParams(new
            {
                roleName = role.RoleName,
                newRole = role
            })
            .ExecuteWithoutResults();
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            _neoClient.Cypher
            .Match("(role:Role)<-[r:MEMBER_OF]-()")
            .Where((Role role) => role.RoleName == roleName)
            .Delete("r, role")
            .ExecuteWithoutResults();

            var roleSearch = _neoClient.Cypher
                .Match("(role:Role)")
                .Where((Role role) => role.RoleName == roleName)
                .Return(role => role.As<Role>())
                .Results;

            return roleSearch.Count() == 0;
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            var userSearch = _neoClient.Cypher
                .OptionalMatch("(user:User)-[:MEMBER_OF]->(role:Role)")
                .Where((Role role) => role.RoleName == roleName)
                .Return(users => users.CollectAs<User>())
                .Results;

            List<string> userList = new List<string>();
            foreach (var u in userSearch)
            {
                userList.Add(u.FirstOrDefault().Data.Username);
            }

            return userList.ToArray();
        }

        public override string[] GetAllRoles()
        {
            var roleSearch = _neoClient.Cypher
                .Match("(role:Role)")
                .Return(roles => roles.CollectAs<Role>())
                .Results;

            List<string> roleList = new List<string>();
            foreach (var r in roleSearch)
            {
                roleList.Add(r.FirstOrDefault().Data.RoleName);
            }

            return roleList.ToArray();
        }

        public override string[] GetRolesForUser(string username)
        {
            var roleSearch = _neoClient.Cypher
                .Match("(user:User)-[:MEMBER_OF]->(role:Role)")
                .Where((User user) => user.Username == username)
                .Return(role => role.As<Role>())
                .Results;

            List<string> roleList = new List<string>();
            foreach (var r in roleSearch)
            {
                roleList.Add(r.RoleName);
            }

            return roleList.ToArray();
        }

        public override string[] GetUsersInRole(string roleName)
        {
            var userSearch = _neoClient.Cypher
                .Match("(user:User)-[:MEMBER_OF]->(role:Role)")
                .Where((Role role) => role.RoleName == roleName)
                .Return(user => user.As<User>())
                .Results;

            List<string> userList = new List<string>();
            foreach (var u in userSearch)
            {
                userList.Add(u.Username);
            }

            return userList.ToArray();
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            var userSearch = _neoClient.Cypher
                .Match("(user:User)-[:MEMBER_OF]->(role:Role)")
                .Where((Role role) => role.RoleName == roleName)
                .AndWhere((User user) => user.Username == username)
                .Return(user => user.As<User>())
                .Results;

            return userSearch.Count() > 0;
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            try
            {
                foreach (string username in usernames)
                {
                    Node<User> u = _neoClient.Cypher
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == applicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                    if (u != null)
                    {
                        List<Node<Role>> roles = _neoClient.Cypher
                          .Match("(n:Role)")
                          .Return<Node<Role>>("n").Results.ToList();
                        foreach (var r in roles)
                        {
                            foreach (string roleName in roleNames)
                            {
                                if (r.Data.RoleName == roleName)
                                {
                                    _neoClient.Cypher
                                        .Match("(user:User)-[r:MEMBER_OF]->(role:Role)")
                                        .Where((User user) => user.Username == username)
                                        .AndWhere((Role role) => role.RoleName == roleName)
                                        .Delete("r")
                                        .ExecuteWithoutResults();
                                }
                            }
                        }
                    }
                }
            }
            catch
            {

            }
        }

        public override bool RoleExists(string roleName)
        {
            List<Node<Role>> roles = _neoClient.Cypher
                          .Match("(n:Role)")
                          .Return<Node<Role>>("n").Results.ToList();

            foreach (Node<Role> role in roles)
            {
                if (role.Data.RoleName == roleName)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Get config value.
        /// </summary>
        /// <param name="configValue"></param>
        /// <param name="defaultValue"></param>
        /// <returns></returns>
        private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
            {
                return defaultValue;
            }

            return configValue;
        }
    }
}
