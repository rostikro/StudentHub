using System;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.Text.Json.Serialization;
using Newtonsoft.Json;
using System.Globalization;

namespace SoftServeProject3.Core.DTOs
{
    [BsonIgnoreExtraElements]
    public class UserModel
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
        
        [JsonProperty("friends")]
        [BsonElement("friends")]
        public List<ObjectId> Friends { get; set; }
        
        [JsonProperty("incomingFriendRequests")]
        [BsonElement("incomingFriendRequests")]
        public List<ObjectId> IncomingFriendRequests { get; set; }
        
        [JsonProperty("outgoingFriendRequests")]
        [BsonElement("outgoingFriendRequests")]
        public List<ObjectId> OutgoingFriendRequests { get; set; }
        
        [JsonProperty("recentlyViewed")]
        [BsonElement("recentlyViewed")]
        public List<ObjectId> RecentlyViewed { get; set; }
        
        [JsonProperty("schedule")]
        [BsonElement("schedule")]
        public Dictionary<string, List<TimeRange>> Schedule { get; set; } //= new ();

        [JsonProperty("isProfilePrivate")]
        [BsonElement("isProfilePrivate")]
        public bool IsProfilePrivate { get; set; }

        [JsonProperty("isFriendsPrivate")]
        [BsonElement("isFriendsPrivate")]
        public bool IsFriendsPrivate { get; set; }

        [JsonProperty("isProfileVerified")]
        [BsonElement("isProfileVerified")]
        public bool IsProfileVerified { get; set; }
    }
    public class ScheduleDay
    {
        public string DayOfWeek { get; set; }
        public List<TimeRange> TimeSlots { get; set; }
    }
    
}