﻿using System;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace SoftServeProject3.Api.Entities
{
    public class User
    {
        public ObjectId _id { get; set; }
        
        [BsonElement("username")]
        public string Username { get; set; }

        [BsonElement("email")]
        public string Email { get; set; }

        [BsonElement("password")]
        public string Password { get; set; }
        
        [BsonElement("isEmailConfirmed")]
        public bool IsEmailConfirmed { get; set; }
    }
}