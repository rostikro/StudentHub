using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace SoftServeProject3.Core.DTOs
{
    public class ForgotPasswordModel
    {
        public ObjectId _id { get; set; }

        [BsonElement("email")]
        public string Email { get; set; }

        [BsonRequired]
        [BsonElement("code")]
        public string Code { get; set; }

        [BsonElement("resendCode")]
        public DateTime ResendCode { get; set; }

        [BsonElement("expirationTime")]
        public DateTime ExpirationTime { get; set; }
    }
}
