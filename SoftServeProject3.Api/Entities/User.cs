using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json.Serialization;
using Newtonsoft.Json;

namespace SoftServeProject3.Api.Entities
{
    public class User
    {
        [System.Text.Json.Serialization.JsonIgnore]
        public ObjectId _id { get; set; }
        
        [JsonProperty("username")]
        [BsonElement("username")]
        public string Username { get; set; }

        [JsonProperty("email")]
        [BsonElement("email")]
        public string Email { get; set; }
      
        [JsonProperty("password")]
        [BsonElement("password")]
        public string Password { get; set; }
        
        [JsonProperty("isEmailConfirmed")]
        [BsonElement("isEmailConfirmed")]
        public bool IsEmailConfirmed { get; set; }

        [JsonProperty("photoUrl")]
        [BsonElement("photoUrl")]
        public string PhotoUrl { get; set; }

        [JsonProperty("faculty")]
        [BsonElement("faculty")]
        public string Faculty { get; set; }

        [JsonProperty("name")]
        [BsonElement("name")]
        public string Name { get; set; }

        [JsonProperty("description")]
        [BsonElement("description")]
        public string Description { get; set; }

        [JsonProperty("subjects")]
        [BsonElement("subjects")]
        public List<string> Subjects { get; set; }

        [JsonProperty("social")]
        [BsonElement("social")]
        public Dictionary<string, string> Social { get; set; }

        [JsonProperty("schedule")]
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