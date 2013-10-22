using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nextwave.Neo4J.Membership.Data
{   
    public class User 
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string ApplicationName { get; set; }
        public string Comment { get; set; }
        public DateTimeOffset CreationDate { get; set; }
        public bool IsApproved { get; set; }
        public DateTimeOffset LastActivityDate { get; set; }        
        public Int64 ProviderUserKey { get; set; }
        public string PasswordQuestion { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTimeOffset LastLoginDate { get; set; }
        public DateTimeOffset LastPasswordChangedDate { get; set; }
        public DateTimeOffset LastLockedOutDate { get; set; }
        public string Password { get; set; }
        public string PasswordAnswer { get; set; }
        public Int64 FailedPasswordAttemptCount { get; set; }
        public DateTimeOffset FailedPasswordAttemptWindowStart { get; set; }
        public Int64 FailedPasswordAnswerAttemptCount { get; set; }
        public DateTimeOffset FailedPasswordAnswerAttemptWindowStart { get; set; }
        public string ResetToken { get; set; }
        public DateTimeOffset ResetTokenExpire { get; set; }
        public string AccountConfirmToken { get; set; }
        public bool IsConfirmed { get; set; }

    }
}
