using MongoDB.Bson;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SoftServeProject3.Core.DTOs
{
    public class UpdateProfile
    {
        [UsernameValidation(4, 100, @"^[a-zA-Z0-9._~-]+$")]
        public string username { get; set; }

        public string photoUrl { get; set; }

        public string faculty { get; set; }

        public string name { get; set; }

        public string description { get; set; }
        public bool isprofileprivate { get; set; }

        public bool isProfileVerified { get; set; }

        public bool isfriendsprivate { get; set; }
        public List<string> subjects { get; set; }

        public Dictionary<string, string> social { get; set; }


        public Dictionary<string, List<TimeRange>> schedule { get; set; }

    }

    public class UsernameValidationAttribute : ValidationAttribute
    {
        private readonly int _minLength;
        private readonly int _maxLength;
        private readonly string _regex;

        public UsernameValidationAttribute(int minLength, int maxLength, string regex)
        {
            _minLength = minLength;
            _maxLength = maxLength;
            _regex = regex;
        }

        protected override ValidationResult IsValid(object? value, ValidationContext validationContext)
        {
            var str = value as string;
            if (str != null)
            {
                if (str.Length < _minLength || str.Length > _maxLength)
                {
                    return new ValidationResult($"Нікнейм повинен бути щонайменше {_minLength} знаків у довжину.");
                }

                if (!Regex.IsMatch(str, _regex))
                {
                    return new ValidationResult("Використовуйте лише латинь, цифри та спеціальні знаки для нікнейму.");
                }
            }

            return ValidationResult.Success;
        }
    }
}