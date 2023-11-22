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
        public TimeOnly StartTime
        {
            get => TimeOnly.Parse(StartString);
            set => StartString = value.ToString("HH:mm");
        }

        [BsonIgnore]
        public TimeOnly EndTime
        {
            get => TimeOnly.Parse(EndString);
            set => EndString = value.ToString("HH:mm");
        }

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
        public bool ValidateTimeFormat(string time, out DateTime parsedTime)
        {
            return DateTime.TryParseExact(time, "HH:mm", CultureInfo.InvariantCulture, DateTimeStyles.None, out parsedTime);
        }

        public bool IsEndTimeAfterStartTime(string startTimeString, string endTimeString)
        {
            if (ValidateTimeFormat(startTimeString, out var startTime) && ValidateTimeFormat(endTimeString, out var endTime))
            {
                return endTime > startTime;
            }
            return false;
        }
        public bool IsOverlappingWith(TimeRange other)
        {
            return (Start < other.End && End > other.Start);
        }
    }
}
