﻿using System;

using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json.Serialization;

namespace SoftServeProject3.Api.Entities
{
    public class User
    {
        public ObjectId _id { get; set; }
        
        [BsonElement("username")]
        public string Username { get; set; }

        [BsonElement("email")]
        public string Email { get; set; }

        [JsonIgnore]
        [BsonElement("password")]
        public string Password { get; set; }
        
        [BsonElement("isEmailConfirmed")]
        public bool IsEmailConfirmed { get; set; }

        [BsonElement("photoUrl")]
        public string PhotoUrl { get; set; }

        [BsonElement("faculty")]
        public string Faculty { get; set; }

        [BsonElement("name")]
        public string Name { get; set; }

        [BsonElement("desription")]
        public string Desription { get; set; }

        [BsonElement("subjects")]
        public List<string> Subjects { get; set; }

        [BsonElement("social")]
        public Dictionary<string, string> Social { get; set; }
        [BsonElement("schedule")]
        public Dictionary<string, List<TimeRange>> Schedule { get; set; }
    }
    public class ScheduleDay
    {
        public string DayOfWeek { get; set; }
        public List<TimeRange> TimeSlots { get; set; }
    }
    public class TimeRange
    {
        [BsonElement("Start")]
        public DateTime Start { get; set; }

        [BsonElement("End")]
        public DateTime End { get; set; }
    }
}