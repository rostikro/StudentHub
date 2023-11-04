namespace SoftServeProject3.Core.DTOs
{
    public class UpdateProfile
    {
        public string authToken { get; set; }

        public string username { get; set; }

        public string photoUrl { get; set; }

        public string faculty { get; set; }

        public string name { get; set; }

        public string description { get; set; }

        public List<string> subjects { get; set; }

        public Dictionary<string, string> social { get; set; }

        public Dictionary<string, List<TimeRange>> schedule { get; set; }
    }
}