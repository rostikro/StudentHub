using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class UserPair
    {
        public ObjectId Id { get; set; }
        public List<string> Users { get; set; }
        public ObjectId? ChatId { get; set; }
        public DateTime LastMessageTimestamp { get; set; }
    }
}
