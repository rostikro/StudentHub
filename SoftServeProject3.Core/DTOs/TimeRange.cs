using MongoDB.Bson.Serialization.Attributes;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class TimeRange
    {
        [BsonElement("Start")]
        public DateTime Start { get; set; }

        [BsonElement("End")]
        public DateTime End { get; set; }

        
        [BsonIgnore]
        public string StartString
        {
            get { return Start.ToString("HH:mm"); }
            set { Start = DateTime.ParseExact(value, "HH:mm", CultureInfo.InvariantCulture); }
        }

        [BsonIgnore]
        public string EndString
        {
            get { return End.ToString("HH:mm"); }
            set { End = DateTime.ParseExact(value, "HH:mm", CultureInfo.InvariantCulture); }
        }
    }
}
