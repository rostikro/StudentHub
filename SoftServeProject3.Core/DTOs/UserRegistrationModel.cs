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
    public class UserRegistrationModel
    {
        [Required(ErrorMessage = "Необхідно ввести нікнейм.")]
        [CustomValidation(4, 100, @"^[a-zA-Z0-9._~-]+$")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Необхідно ввести пошту.")]
        [EmailValidation]
        public string Email { get; set; }

        [Required(ErrorMessage = "Необхідно ввести пароль.")]
        [StringLength(100, ErrorMessage = "Пароль повинен бути щонайменше {2} знаків у довжину.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Необхідно ввести підтвердження паролю.")]
        [Compare("Password", ErrorMessage = "Паролі не співпадають.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }

    //клас для валідація поля нікнейму: тільки якщо валідація на знаки в довжину проходить - здійснюється валідація знаків
    public class CustomValidationAttribute : ValidationAttribute
    {
        private readonly int _minLength;
        private readonly int _maxLength;
        private readonly string _regex;

        public CustomValidationAttribute(int minLength, int maxLength, string regex)
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

    public class EmailValidation : ValidationAttribute
    {
        protected override ValidationResult IsValid(object? value, ValidationContext validationContext)
        {
            var email = value as string;

            var emailRegex = new Regex(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$");
            var emailAttr = new EmailAddressAttribute();

            if (!emailAttr.IsValid(email) || !emailRegex.IsMatch(email))
            {
                return new ValidationResult("Неправильний формат пошти.");
            }

            return ValidationResult.Success;

        }
    }

}
