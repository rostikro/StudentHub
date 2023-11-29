using MongoDB.Bson;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SoftServeProject3.Core.DTOs
{
    public class Chat
    {
        public ObjectId Id { get; set; }
        public List<Message> Messages { get; set; }
    }
}
