using System.Web.Security;
using System.Configuration.Provider;
using System.Collections.Generic;
using System.Collections.Specialized;
using System;
using System.Data;
using System.Data.Linq;
using System.Linq;
using System.Configuration;
using System.Diagnostics;
using System.Web;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web.Configuration;
using System.Text.RegularExpressions;

using WebMatrix.WebData;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Nextwave.Neo4J.Membership.Data;
using Neo4jClient;

namespace Nextwave.Neo4J.Membership
{
    public sealed class Neo4JMembershipProvider : ExtendedMembershipProvider
    {

        private GraphClient _neoClient = null;

        //
        // Global connection string, generated password length, generic exception message, event log info.
        //

        private int newPasswordLength = 8;
        private string eventSource = "Neo4JMembershipProvider";
        private string eventLog = "Application";
        private string exceptionMessage = "An exception occurred. Please check the Event Log.";
        private string connectionString;

        //
        // Used when determining encryption key values.
        //

        private MachineKeySection machineKey;

        //
        // If false, exceptions are thrown to the caller. If true,
        // exceptions are written to the event log.
        //

        private bool pWriteExceptionsToEventLog;

        public bool WriteExceptionsToEventLog
        {
            get { return pWriteExceptionsToEventLog; }
            set { pWriteExceptionsToEventLog = value; }
        }


        //
        // System.Configuration.Provider.ProviderBase.Initialize Method
        //

        public override void Initialize(string name, NameValueCollection config)
        {
            //
            // Initialize values from web.config.
            //
            if (config == null)
            {
                throw new ArgumentNullException("config");
            }

            if (name == null || name.Length == 0)
            {
                name = "Neo4JMembershipProvider";
            }

            if (String.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Neo4J Membership provider");
            }

            // Initialize the abstract base class.
            base.Initialize(name, config);

            pApplicationName = GetConfigValue(config["applicationName"],System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            pMaxInvalidPasswordAttempts = Convert.ToInt32(GetConfigValue(config["maxInvalidPasswordAttempts"], "5"));
            pPasswordAttemptWindow = Convert.ToInt32(GetConfigValue(config["passwordAttemptWindow"], "10"));
            pMinRequiredNonAlphanumericCharacters = Convert.ToInt32(GetConfigValue(config["minRequiredNonAlphanumericCharacters"], "1"));
            pMinRequiredPasswordLength = Convert.ToInt32(GetConfigValue(config["minRequiredPasswordLength"], "7"));
            pPasswordStrengthRegularExpression = Convert.ToString(GetConfigValue(config["passwordStrengthRegularExpression"], ""));
            pEnablePasswordReset = Convert.ToBoolean(GetConfigValue(config["enablePasswordReset"], "true"));
            pEnablePasswordRetrieval = Convert.ToBoolean(GetConfigValue(config["enablePasswordRetrieval"], "true"));
            pRequiresQuestionAndAnswer = Convert.ToBoolean(GetConfigValue(config["requiresQuestionAndAnswer"], "false"));
            pRequiresUniqueEmail = Convert.ToBoolean(GetConfigValue(config["requiresUniqueEmail"], "true"));
            pWriteExceptionsToEventLog = Convert.ToBoolean(GetConfigValue(config["writeExceptionsToEventLog"], "true"));

            string temp_format = config["passwordFormat"];
            if (temp_format == null)
            {
                temp_format = "Hashed";
            }

            switch (temp_format)
            {
                case "Hashed":
                    pPasswordFormat = MembershipPasswordFormat.Hashed;
                    break;
                case "Encrypted":
                    pPasswordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Clear":
                    pPasswordFormat = MembershipPasswordFormat.Clear;
                    break;
                default:
                    throw new ProviderException("Password format not supported.");
            }

            //
            // Initialize OdbcConnection.
            //

            ConnectionStringSettings ConnectionStringSettings =
              ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

            

            if (ConnectionStringSettings == null || ConnectionStringSettings.ConnectionString.Trim() == "")
            {
                throw new ProviderException("Connection string cannot be blank.");
            }

            connectionString = ConnectionStringSettings.ConnectionString;

            // CA - init our connection client
            _neoClient = new GraphClient(new Uri(connectionString));
            _neoClient.Connect();
            
            // Get encryption and decryption key information from the configuration.
            Configuration cfg = WebConfigurationManager.OpenWebConfiguration(System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            machineKey = (MachineKeySection)cfg.GetSection("system.web/machineKey");

            if (machineKey.ValidationKey.Contains("AutoGenerate"))
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                    throw new ProviderException("Hashed or Encrypted passwords are not supported with auto-generated keys.");
        }


        //
        // A helper function to retrieve config values from the configuration file.
        //

        private string GetConfigValue(string configValue, string defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
                return defaultValue;

            return configValue;
        }


        #region Extended Membership Provider

        public override bool HasLocalAccount(int userId)
        {
            try
            {
                Node<User> user = _neoClient.Cypher.Start(new { n = _neoClient.RootNode })
                    .Match("(n:User)")
                    .Where((User u) => u.ProviderUserKey == userId && ApplicationName == pApplicationName)
                    .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "HasLocalAccount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }


        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => n.Username == userName && n.ApplicationName == pApplicationName)
                    .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {                  
                    return user.Data.FailedPasswordAttemptWindowStart.DateTime;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetLastPasswordFailureDate");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return DateTime.MinValue;
        }

        public override DateTime GetPasswordChangedDate(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return user.Data.LastPasswordChangedDate.DateTime;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetPasswordChangedDate");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return DateTime.MinValue;
        }

        public override DateTime GetCreateDate(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return user.Data.CreationDate.DateTime;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetCreateDate");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return DateTime.MinValue;
        }

        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return (int)user.Data.FailedPasswordAttemptCount;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetPasswordFailuresSinceLastSuccess");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return 0;
        }

        public override bool ResetPasswordWithToken(string token,string newPassword)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.ResetToken == token && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.Password = EncodePassword(newPassword);
                    });
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ResetPasswordWithToken");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }

        public override bool IsConfirmed(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return user.Data.IsConfirmed;                 
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "IsConfirmed");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }

        public override int GetUserIdFromPasswordResetToken(string token)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.ResetToken == token && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    return (int)user.Reference.Id;
                }
                return -1;                
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetUserIdFromPasswordResetToken");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }         
        }

        public override bool DeleteAccount(string userName)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                _neoClient.Delete(user.Reference, DeleteMode.NodeAndRelationships);
                return true;
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "DeleteAccount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }         
        }

        public override string GeneratePasswordResetToken(string userName,int tokenExpirationInMinutesFromNow)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    string rt = Guid.NewGuid().ToString();
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.ResetToken = rt;
                        u.ResetTokenExpire = DateTime.Now.AddMinutes(tokenExpirationInMinutesFromNow);
                    });
                    return rt;
                }
                
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "DeleteAccount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return string.Empty;
        }

        public override bool ConfirmAccount(string AccountConfirmToken)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.AccountConfirmToken == AccountConfirmToken && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null )
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.IsConfirmed = true;
                    });
                    return true;
                    
                }

            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ConfirmAccount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }

        public override bool ConfirmAccount(string userName, string AccountConfirmToken)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Username == userName && n.AccountConfirmToken == AccountConfirmToken && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.IsConfirmed = true;
                    });
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ConfirmAccount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }

        public override string CreateAccount(string userName, string password)
        {
            return CreateAccount(userName, password, false);
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(userName, password, true);
            OnValidatingPassword(args);

            if (args.Cancel)
            {
                return null;
            }

            MembershipUser u = GetUser(userName, false);

            if (u == null)
            {
                DateTime createDate = DateTime.Now;                
                Guid provider = Guid.NewGuid();
                Guid confirmToke= Guid.NewGuid();
                
                try
                {
                    User user = new User()
                    {
                        Email = userName,
                        // This must be an Int for WebSecurity GetUserId to work
                        // http://aspnetwebstack.codeplex.com/SourceControl/latest#src/WebMatrix.WebData/WebSecurity.cs
                    //    ProviderUserKey = provider,
                        Username = userName,
                        Password = EncodePassword(password),
                        Comment = "",
                        CreationDate = createDate,
                        LastPasswordChangedDate = createDate,
                        LastActivityDate = createDate,
                        ApplicationName = pApplicationName,
                        IsLockedOut = false,
                        IsApproved = true,
                        LastLockedOutDate = createDate,
                        FailedPasswordAttemptCount = 0,
                        FailedPasswordAttemptWindowStart = createDate,
                        FailedPasswordAnswerAttemptCount = 0,
                        FailedPasswordAnswerAttemptWindowStart = createDate,
                        AccountConfirmToken = confirmToke.ToString(),
                        IsConfirmed = requireConfirmationToken
                    };

                    _neoClient.Cypher
                                .Create("(user:User {newUser})")
                                .WithParam("newUser", user)
                                .ExecuteWithoutResults();
                    Node<User> newUser = _neoClient.Cypher
                             .Match("(n:User)")
                             .Where((User n) => (n.Username == userName && n.ApplicationName == pApplicationName))
                             .Return<Node<User>>("n").Results.FirstOrDefault();

                    if (newUser != null)
                    {
                        // we need to update the provider token...
                        _neoClient.Update<User>(newUser.Reference, un =>
                        {
                            un.ProviderUserKey = newUser.Reference.Id;
                        });
                        return newUser.Data.AccountConfirmToken;
                    }
                    else
                    {
                        return null;
                    }
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "CreateAccount");
                    }

                }
            }           
            return null;
        }


        public override string CreateUserAndAccount(string userName, string password)
        {
            // TODO: we use the same facilities for account and user
            return CreateAccount(userName, password, false);
        }

        public override string CreateUserAndAccount(string userName, string password, IDictionary<string, object> values)
        {
            // TODO: we use the same facilities for account and user
            // We ignore the values sent through here...
            return CreateAccount(userName, password, false);
        }
        public override string GetUserNameFromId(int userId)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.ProviderUserKey == userId && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null )
                {
                    return user.Data.Username;
                }

            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetUserNameFromId");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return string.Empty;
        }


        
        public override void DeleteOAuthAccount(string provider, string providerUserId)
        {
            throw new NotImplementedException();
        }
        public override void DeleteOAuthToken(string token)
        {
            throw new NotImplementedException();
        }

        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {
            // TODO: we use the same facilities for account and user
            // We ignore the values sent through here...
            return CreateAccount(userName, password, requireConfirmation);
        }
        public override string GetOAuthTokenSecret(string token)
        {
        //    throw new NotImplementedException();
            return "";
        }
        public override int GetUserIdFromOAuth(string provider, string providerUserId)
        {
        //    throw new NotImplementedException();
            return -1; // -1 is no user for that OAuth provider
        }
        public override void ReplaceOAuthRequestTokenWithAccessToken(string requestToken, string accessToken, string accessTokenSecret)
        {
        //    throw new NotImplementedException();
        }
        public override void StoreOAuthRequestToken(string requestToken, string requestTokenSecret)
        {
        //    throw new NotImplementedException();
        }
        public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
        {
        //    hack = providerUserId;
            //throw new NotImplementedException();
        }
        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {   // TODO: 
            IList<OAuthAccountData> ret = new List<OAuthAccountData>();
            return ret;
        }

       

        #endregion

        //
        // System.Web.Security.MembershipProvider properties.
        //

        #region System.Web.Security.MembershipProvider properties

        private string pApplicationName;
        private bool pEnablePasswordReset;
        private bool pEnablePasswordRetrieval;
        private bool pRequiresQuestionAndAnswer;
        private bool pRequiresUniqueEmail;
        private int pMaxInvalidPasswordAttempts;
        private int pPasswordAttemptWindow;
        private MembershipPasswordFormat pPasswordFormat;

        public override string ApplicationName
        {
            get { return pApplicationName; }
            set { pApplicationName = value; }
        }

        public override bool EnablePasswordReset
        {
            get { return pEnablePasswordReset; }
        }


        public override bool EnablePasswordRetrieval
        {
            get { return pEnablePasswordRetrieval; }
        }


        public override bool RequiresQuestionAndAnswer
        {
            get { return pRequiresQuestionAndAnswer; }
        }


        public override bool RequiresUniqueEmail
        {
            get { return pRequiresUniqueEmail; }
        }


        public override int MaxInvalidPasswordAttempts
        {
            get { return pMaxInvalidPasswordAttempts; }
        }


        public override int PasswordAttemptWindow
        {
            get { return pPasswordAttemptWindow; }
        }


        public override MembershipPasswordFormat PasswordFormat
        {
            get { return pPasswordFormat; }
        }

        private int pMinRequiredNonAlphanumericCharacters;

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return pMinRequiredNonAlphanumericCharacters; }
        }

        private int pMinRequiredPasswordLength;

        public override int MinRequiredPasswordLength
        {
            get { return pMinRequiredPasswordLength; }
        }

        private string pPasswordStrengthRegularExpression;

        public override string PasswordStrengthRegularExpression
        {
            get { return pPasswordStrengthRegularExpression; }
        }

        #endregion

        //
        // System.Web.Security.MembershipProvider methods.
        //

        //
        // MembershipProvider.ChangePassword
        //

        public override bool ChangePassword(string username, string oldPwd, string newPwd)
        {
            if (!ValidateUser(username, oldPwd))
                return false;


            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPwd, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                if (args.FailureInformation != null)
                {
                    throw args.FailureInformation;
                }
                else
                {
                    throw new MembershipPasswordException("Change password canceled due to new password validation failure.");
                }
            }

            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.Password = EncodePassword(newPwd);
                        u.LastPasswordChangedDate = DateTime.Now;
                    });
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ChangePassword");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }         
            return false;
        }



        //
        // MembershipProvider.ChangePasswordQuestionAndAnswer
        //

        public override bool ChangePasswordQuestionAndAnswer(string username,
                      string password,
                      string newPwdQuestion,
                      string newPwdAnswer)
        {
            if (!ValidateUser(username, password))
                return false;

            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.PasswordQuestion = newPwdQuestion;
                        u.PasswordAnswer = EncodePassword(newPwdAnswer);
                    });
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ChangePasswordQuestionAndAnswer");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }



        //
        // MembershipProvider.CreateUser
        //

        public override MembershipUser CreateUser(string username,
                 string password,
                 string email,
                 string passwordQuestion,
                 string passwordAnswer,
                 bool isApproved,
                 object providerUserKey,
                 out MembershipCreateStatus status)
        {
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, password, true);
            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (RequiresUniqueEmail && GetUserNameByEmail(email) != "")
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            MembershipUser u = GetUser(username, false);

            if (u == null)
            {
                DateTime createDate = DateTime.Now;
                if (providerUserKey == null)
                {
                    providerUserKey = Guid.NewGuid();
                }
                else
                {
                    if (!(providerUserKey is Guid))
                    {
                        status = MembershipCreateStatus.InvalidProviderUserKey;
                        return null;
                    }
                }

                User user = new User()
                    {
                        Email = email,
                  //      ProviderUserKey = providerUserKey,
                        Username = username,
                        Password = EncodePassword(password),
                        PasswordQuestion = passwordQuestion,
                        PasswordAnswer = EncodePassword(passwordAnswer),
                        IsApproved = isApproved,
                        Comment = "",
                        CreationDate = createDate,
                        LastPasswordChangedDate = createDate,
                        LastActivityDate = createDate,
                        ApplicationName = pApplicationName,
                        IsLockedOut = false,
                        LastLockedOutDate = createDate,
                        FailedPasswordAttemptCount = 0,
                        FailedPasswordAttemptWindowStart = createDate,
                        FailedPasswordAnswerAttemptCount = 0,
                        FailedPasswordAnswerAttemptWindowStart = createDate
                    };

                try
                {
                    _neoClient.Cypher
                                .Create("(user:User {newUser})")
                                .WithParam("newUser", user)
                                .ExecuteWithoutResults();
                    Node<User> newUser = _neoClient.Cypher
                             .Match("(n:User)")
                             .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                             .Return<Node<User>>("n").Results.FirstOrDefault();

                    if (newUser != null) 
                    {
                        // ProviderUserKey must be an int for WebSecurity to work right...
                        // http://aspnetwebstack.codeplex.com/SourceControl/latest#src/WebMatrix.WebData/WebSecurity.cs
                        _neoClient.Update<User>(newUser.Reference, un =>
                        {
                            un.ProviderUserKey = newUser.Reference.Id;
                        });
                        newUser.Data.ProviderUserKey = (int)newUser.Reference.Id;
                        status = MembershipCreateStatus.Success;
                    }
                    else
                    {
                        status = MembershipCreateStatus.ProviderError;
                    }
                }
                catch (Exception e)
                {
                    if (WriteExceptionsToEventLog)
                    {
                        WriteToEventLog(e, "CreateUser");
                    }

                    status = MembershipCreateStatus.ProviderError;
                }               
                return GetUser(username, false);
            }
            else
            {
                status = MembershipCreateStatus.DuplicateUserName;
            }
            return null;
        }



        //
        // MembershipProvider.DeleteUser
        //
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    _neoClient.Delete(user.Reference, deleteAllRelatedData ? DeleteMode.NodeAndRelationships : DeleteMode.NodeOnly);
                }
                return true;
                
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "DeleteUser");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }                        
        }



        //
        // MembershipProvider.GetAllUsers
        //

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection mUserCollection = new MembershipUserCollection();
            totalRecords = 0;

            try
            {

                Node<User>[] users = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => n.ApplicationName == pApplicationName)
                    .Return<Node<User>>("n").Skip(pageIndex * pageSize).Limit(pageSize).Results.ToArray();
                totalRecords = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => n.ApplicationName == pApplicationName)
                    .Return<int>("COUNT(n)").Results.First();
                if (users != null)
                {
                    foreach (Node<User> nu in users)
                    {
                        // NOTE: this is a required conversion to avoid a class cast exception in WebMatrix.WebData.WebSecurity.cs                    
                        int puId = (int)nu.Reference.Id;
                        User u = nu.Data;
                        mUserCollection.Add(new MembershipUser(this.Name,
                                                      u.Username,
                                                      puId,
                                                      u.Email,
                                                      u.PasswordQuestion,
                                                      u.Comment,
                                                      u.IsApproved,
                                                      u.IsLockedOut,
                                                      u.CreationDate.DateTime,
                                                      u.LastLoginDate.DateTime,
                                                      u.LastActivityDate.DateTime,
                                                      u.LastPasswordChangedDate.DateTime,
                                                      u.LastLockedOutDate.DateTime));
                    }
                    return mUserCollection;
                }

            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetAllUsers ");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }         
            return mUserCollection;
        }


        //
        // MembershipProvider.GetNumberOfUsersOnline
        //

        public override int GetNumberOfUsersOnline()
        {

            TimeSpan onlineSpan = new TimeSpan(0, System.Web.Security.Membership.UserIsOnlineTimeWindow, 0);
            DateTime compareTime = DateTime.Now.Subtract(onlineSpan);

            try
            {
                Int64 total = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => n.LastActivityDate < compareTime &&  n.ApplicationName == pApplicationName)
                    .Return<int>("COUNT(n)").Results.First();

                // TODO: need a date compare op..
                //OdbcCommand cmd = new OdbcCommand("SELECT Count(*) FROM Users " +
                //    " WHERE LastActivityDate > ? AND ApplicationName = ?", conn);
                return (int)total;
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetNumberOfUsersOnline");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
        }



        //
        // MembershipProvider.GetPassword
        //

        public override string GetPassword(string username, string answer)
        {
            if (!EnablePasswordRetrieval)
            {
                throw new ProviderException("Password Retrieval Not Enabled.");
            }
            if (PasswordFormat == MembershipPasswordFormat.Hashed)
            {
                throw new ProviderException("Cannot retrieve Hashed passwords.");
            }
            string password = string.Empty;
            string passwordAnswer = string.Empty;

            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    if (user.Data.IsLockedOut)
                    {
                        new MembershipPasswordException("The supplied user is locked out.");
                    }
                    password = user.Data.Password;
                    passwordAnswer = user.Data.PasswordAnswer;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetPassword");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            if (RequiresQuestionAndAnswer && !CheckPassword(answer, passwordAnswer))
            {
                UpdateFailureCount(username, "passwordAnswer");
                throw new MembershipPasswordException("Incorrect password answer.");
            }
            if (PasswordFormat == MembershipPasswordFormat.Encrypted)
            {
                password = UnEncodePassword(password);
            }
            return password;
        }



        //
        // MembershipProvider.GetUser(string, bool)
        //

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {            
                    if (userIsOnline)
                    {
                        _neoClient.Update(user.Reference, un =>
                        {
                            un.LastActivityDate = DateTime.Now;
                        });                                        
                    }
                    // NOTE: this is a required conversion to avoid a class cast exception in WebMatrix.WebData.WebSecurity.cs                    
                    int puId = (int)user.Reference.Id;
                    User u = user.Data;
                    return  new MembershipUser(this.Name,
                                                  u.Username,
                                                  puId,
                                                  u.Email,
                                                  u.PasswordQuestion,
                                                  u.Comment,
                                                  u.IsApproved,
                                                  u.IsLockedOut,
                                                  u.CreationDate.DateTime,
                                                  u.LastLoginDate.DateTime,
                                                  u.LastActivityDate.DateTime,
                                                  u.LastPasswordChangedDate.DateTime,
                                                  u.LastLockedOutDate.DateTime);                    
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetUser(String, Boolean)");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return null;    
        }


        //
        // MembershipProvider.GetUser(object, bool)
        //

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.ProviderUserKey == (int)providerUserKey && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();
                if (user != null)
                {
                    if (userIsOnline)
                    {
                        _neoClient.Update(user.Reference, uu =>
                        {
                            uu.LastActivityDate = DateTime.Now;
                        });                                         
                    }
                    // NOTE: this is a required conversion to avoid a class cast exception in WebMatrix.WebData.WebSecurity.cs                    
                    int puId = (int)user.Reference.Id;
                    User u = user.Data;
                    return new MembershipUser(this.Name,
                                                  u.Username,
                                                  puId,
                                                  u.Email,
                                                  u.PasswordQuestion,
                                                  u.Comment,
                                                  u.IsApproved,
                                                  u.IsLockedOut,
                                                  u.CreationDate.DateTime,
                                                  u.LastLoginDate.DateTime,
                                                  u.LastActivityDate.DateTime,
                                                  u.LastPasswordChangedDate.DateTime,
                                                  u.LastLockedOutDate.DateTime);
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetUser(String, Boolean)");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return null;    
        }       


        //
        // MembershipProvider.UnlockUser
        //

        public override bool UnlockUser(string username)
        {            
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                  .Match("(n:User)")
                  .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                  .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.IsLockedOut = false;
                        u.LastLockedOutDate = DateTime.Now; 
                    });
                    return true;
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "UnlockUser");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return false;
        }


        //
        // MembershipProvider.GetUserNameByEmail
        //
        public override string GetUserNameByEmail(string email)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                 .Match("(n:User)")
                 .Where((User n) => (n.Email == email && n.ApplicationName == pApplicationName))
                 .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    return user.Data.Username;
                }
            }
            catch(Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "GetUserNameByEmail");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            return string.Empty;           
        }




        //
        // MembershipProvider.ResetPassword
        //
        public override string ResetPassword(string username, string answer)
        {
            if (!EnablePasswordReset)
            {
                throw new NotSupportedException("Password reset is not enabled.");
            }

            if (answer == null && RequiresQuestionAndAnswer)
            {
                UpdateFailureCount(username, "passwordAnswer");
                throw new ProviderException("Password answer required for password reset.");
            }

            string newPassword = System.Web.Security.Membership.GeneratePassword(newPasswordLength, MinRequiredNonAlphanumericCharacters);
            ValidatePasswordEventArgs args = new ValidatePasswordEventArgs(username, newPassword, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                if (args.FailureInformation != null)
                {
                    throw args.FailureInformation;
                }
                else
                {
                    throw new MembershipPasswordException("Reset password canceled due to password validation failure.");
                }
            }
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                 .Match("(n:User)")
                 .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName))
                 .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    if (RequiresQuestionAndAnswer && !CheckPassword(answer, user.Data.PasswordAnswer))
                    {
                        UpdateFailureCount(username, "passwordAnswer");
                        throw new MembershipPasswordException("Incorrect password answer.");
                    }
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.Password = EncodePassword(newPassword);
                        u.LastPasswordChangedDate = DateTime.Now;
                    });                    
                    return newPassword;                    
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ResetPassword");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
            throw new MembershipPasswordException("User not found, or user is locked out. Password not Reset.");
        }


        //
        // MembershipProvider.UpdateUser
        //

        public override void UpdateUser(MembershipUser muser)
        {
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                 .Match("(n:User)")
                 .Where((User n) => (n.ProviderUserKey == (int)muser.ProviderUserKey && n.ApplicationName == pApplicationName))
                 .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null )
                {
                    _neoClient.Update(user.Reference, u =>
                    {
                        u.Email = muser.Email;
                        u.Comment = muser.Comment;
                        u.IsApproved = muser.IsApproved;
                        u.Username = muser.UserName;
                        u.ApplicationName = pApplicationName;
                    });                   
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "UpdateUser");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }

        }


        //
        // MembershipProvider.ValidateUser
        //

        public override bool ValidateUser(string username, string password)
        {
            bool isValid = false;
            try
            {
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName && n.IsLockedOut == false))
                    .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    if (user.Data.IsApproved && CheckPassword(password, user.Data.Password))
                    {
                        isValid = true;
                        DateTimeOffset LastLoginDate = new DateTimeOffset(DateTime.Now);
                        _neoClient.Update(user.Reference, u =>
                        {
                            u.LastLoginDate = LastLoginDate;
                        });
                        //_neoClient.Update<User>(user, new { UserName = username, ApplicationName = pApplicationName });                       
                    }
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "ValidateUser");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }

            return isValid;
        }


        //
        // UpdateFailureCount
        //   A helper method that performs the checks and updates associated with
        // password failure tracking.
        //

        private void UpdateFailureCount(string username, string failureType)
        {

            try
            {
                DateTime windowStart = new DateTime();
                Int64 failureCount = 0;
                
                Node<User> user = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                .Match("(n:User)")
                .Where((User n) => (n.Username == username && n.ApplicationName == pApplicationName && n.IsLockedOut == false))
                .Return<Node<User>>("n").Results.FirstOrDefault();

                if (user != null)
                {
                    if (failureType == "password")
                    {
                        failureCount = user.Data.FailedPasswordAttemptCount;
                        windowStart = user.Data.FailedPasswordAttemptWindowStart.DateTime;
                    }
                    if (failureType == "passwordAnswer")
                    {
                        failureCount = user.Data.FailedPasswordAnswerAttemptCount;
                        windowStart = user.Data.FailedPasswordAnswerAttemptWindowStart.DateTime;
                    }
                    DateTime windowEnd = windowStart.AddMinutes(PasswordAttemptWindow);
                    if (failureCount == 0 || DateTime.Now > windowEnd)
                    {
                        // First password failure or outside of PasswordAttemptWindow. 
                        // Start a new password failure count from 1 and a new window starting now.

                        if (failureType == "password")
                        {
                            user.Data.FailedPasswordAttemptCount = 1;
                            user.Data.FailedPasswordAttemptWindowStart = DateTime.Now;              
                        }

                        if (failureType == "passwordAnswer")
                        {
                            user.Data.FailedPasswordAnswerAttemptCount = 1;
                            user.Data.FailedPasswordAnswerAttemptWindowStart = DateTime.Now;                           
                        }
                    }
                    else
                    {
                        if (failureCount++ >= MaxInvalidPasswordAttempts)
                        {
                            // Password attempts have exceeded the failure threshold. Lock out
                            // the user.
                            user.Data.IsLockedOut = true;
                            user.Data.LastLockedOutDate = DateTime.Now;                            
                        }
                        else
                        {
                            // Password attempts have not exceeded the failure threshold. Update
                            // the failure counts. Leave the window the same.
                            if (failureType == "password")
                            {
                                user.Data.FailedPasswordAttemptCount++;
                            }
                            if (failureType == "passwordAnswer")
                            {
                                user.Data.FailedPasswordAnswerAttemptCount++;
                            }
                        }
                    }
                    _neoClient.Update<User>(user.Reference, u =>
                    {
                        u.FailedPasswordAttemptCount = user.Data.FailedPasswordAttemptCount;
                        u.FailedPasswordAttemptWindowStart = user.Data.FailedPasswordAttemptWindowStart;
                        u.FailedPasswordAnswerAttemptCount = user.Data.FailedPasswordAnswerAttemptCount;
                        u.FailedPasswordAnswerAttemptWindowStart = user.Data.FailedPasswordAnswerAttemptWindowStart;
                        u.IsLockedOut = user.Data.IsLockedOut;
                        u.LastActivityDate = user.Data.LastLockedOutDate;
                    });
                }
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "UpdateFailureCount");
                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }
        }


        //
        // CheckPassword
        //   Compares password values based on the MembershipPasswordFormat.
        //

        private bool CheckPassword(string password, string dbpassword)
        {
            string pass1 = password;
            string pass2 = dbpassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Encrypted:
                    pass2 = UnEncodePassword(dbpassword);
                    break;
                case MembershipPasswordFormat.Hashed:
                    pass1 = EncodePassword(password);
                    break;
                default:
                    break;
            }

            if (pass1 == pass2)
            {
                return true;
            }

            return false;
        }


        //
        // EncodePassword
        //   Encrypts, Hashes, or leaves the password clear based on the PasswordFormat.
        //

        private string EncodePassword(string password)
        {
            string encodedPassword = password;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    encodedPassword =
                      Convert.ToBase64String(EncryptPassword(Encoding.Unicode.GetBytes(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    HMACSHA1 hash = new HMACSHA1();
                    hash.Key = HexToByte(machineKey.ValidationKey);
                    encodedPassword =
                      Convert.ToBase64String(hash.ComputeHash(Encoding.Unicode.GetBytes(password)));
                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return encodedPassword;
        }


        //
        // UnEncodePassword
        //   Decrypts or leaves the password clear based on the PasswordFormat.
        //

        private string UnEncodePassword(string encodedPassword)
        {
            string password = encodedPassword;

            switch (PasswordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    password =
                      Encoding.Unicode.GetString(DecryptPassword(Convert.FromBase64String(password)));
                    break;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Cannot unencode a hashed password.");
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return password;
        }

        //
        // HexToByte
        //   Converts a hexadecimal string to a byte array. Used to convert encryption
        // key values from the configuration.
        //

        private byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }


        //
        // MembershipProvider.FindUsersByName
        //

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {

            MembershipUserCollection memUsersCollection = new MembershipUserCollection();
            
            try
            {
                // TDOO: check if we can return "n, COUNT(n)" in one go.. we can for sure in cypher strings
                Node<User>[] users = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => (n.Username.StartsWith(usernameToMatch) && n.ApplicationName == pApplicationName))
                    .Return<Node<User>>("n").Skip(pageIndex*pageSize).Limit(pageSize).Results.ToArray();
                totalRecords = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => (n.Username.StartsWith(usernameToMatch) && n.ApplicationName == pApplicationName))
                    .Return<int>("COUNT(n)").Results.First();


                foreach (Node<User> nu in users)
                {
                    // NOTE: this is a required conversion to avoid a class cast exception in WebMatrix.WebData.WebSecurity.cs                    
                    int puId = (int)nu.Reference.Id;
                    User u = nu.Data;
                    memUsersCollection.Add(new MembershipUser(this.Name,
                                                  u.Username,
                                                  puId,
                                                  u.Email,
                                                  u.PasswordQuestion,
                                                  u.Comment,
                                                  u.IsApproved,
                                                  u.IsLockedOut,
                                                  u.CreationDate.DateTime,
                                                  u.LastLoginDate.DateTime,
                                                  u.LastActivityDate.DateTime,
                                                  u.LastPasswordChangedDate.DateTime,
                                                  u.LastLockedOutDate.DateTime));
                }
                return memUsersCollection;
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "FindUsersByName");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }         
        }

        //
        // MembershipProvider.FindUsersByEmail
        //

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            MembershipUserCollection memUsersCollection = new MembershipUserCollection();

            totalRecords = 0;
            try
            {

                Node<User>[] users = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                   .Match("(n:User)")
                   .Where((User n) => (n.Email.Contains(emailToMatch) && n.ApplicationName == pApplicationName))
                   .Return<Node<User>>("n").Skip(pageIndex * pageSize).Limit(pageSize).Results.ToArray();
                totalRecords = _neoClient.Cypher//.Start( new { n = Neo4jClient.Cypher.All.Nodes})
                    .Match("(n:User)")
                    .Where((User n) => n.ApplicationName == pApplicationName)
                    .Return<int>("COUNT(n)").Results.First();


                foreach (Node<User> nu in users)
                {
                    int puId = (int)nu.Reference.Id;
                    User u = nu.Data;
                    memUsersCollection.Add(new MembershipUser(this.Name,
                                                  u.Username,
                                                  puId,
                                                  u.Email,
                                                  u.PasswordQuestion,
                                                  u.Comment,
                                                  u.IsApproved,
                                                  u.IsLockedOut,
                                                  u.CreationDate.DateTime,
                                                  u.LastLoginDate.DateTime,
                                                  u.LastActivityDate.DateTime,
                                                  u.LastPasswordChangedDate.DateTime,
                                                  u.LastLockedOutDate.DateTime));
                }
                return memUsersCollection;
            }
            catch (Exception e)
            {
                if (WriteExceptionsToEventLog)
                {
                    WriteToEventLog(e, "FindUsersByEmail");

                    throw new ProviderException(exceptionMessage);
                }
                else
                {
                    throw e;
                }
            }

            return memUsersCollection;
        }


        //
        // WriteToEventLog
        //   A helper function that writes exception detail to the event log. Exceptions
        // are written to the event log as a security measure to avoid private database
        // details from being returned to the browser. If a method does not return a status
        // or boolean indicating the action succeeded or failed, a generic exception is also 
        // thrown by the caller.
        //

        private void WriteToEventLog(Exception e, string action)
        {
            EventLog log = new EventLog();
            log.Source = eventSource;
            log.Log = eventLog;

            string message = "An exception occurred communicating with the data source.\n\n";
            message += "Action: " + action + "\n\n";
            message += "Exception: " + e.ToString();

            log.WriteEntry(message);
        }

    }
}
