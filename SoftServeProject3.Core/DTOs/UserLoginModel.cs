using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace SoftServeProject3.Core.DTOs
{
    public class UserLoginModel
    {
        [Required(ErrorMessage = "Необхідно ввести нікнейм або пошту.")]
        [EmailOrUsernameValidation]
        public string EmailorUsername { get; set; }

        [Required(ErrorMessage = "Необхідно ввести пароль.")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }

    public class EmailOrUsernameValidation : ValidationAttribute
    {
        protected override ValidationResult IsValid(object value, ValidationContext validationContext)
        {
            var str = value as string;
            if (str == null)
            {
                return new ValidationResult("Необхідно ввести нікнейм або пошту.");
            }

            if (str.Contains("@"))
            {
                // Validate as email
                var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
                var emailAttr = new EmailAddressAttribute();

                if (!emailAttr.IsValid(str) || !emailRegex.IsMatch(str))
                {
                    return new ValidationResult("Неправильний формат пошти.");
                }
            }
            else
            {
                // Validate as username
                var usernameRegex = new Regex(@"^[a-zA-Z0-9._~-]+$");
                if (!usernameRegex.IsMatch(str) || str.Length < 4 || str.Length > 100)
                {
                    return new ValidationResult("Використовуйте лише латинь, цифри та спеціальні знаки для нікнейму.");
                }
            }

            return ValidationResult.Success;
        }
    }

}
