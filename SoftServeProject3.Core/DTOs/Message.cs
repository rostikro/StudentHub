using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class Message
    {
        public ObjectId Id { get; set; } 
        public string SenderUsername { get; set; }
        public string ReceiverUsername { get; set; }
        public string Text { get; set; }
        public DateTime Timestamp { get; set; }
    }
}
