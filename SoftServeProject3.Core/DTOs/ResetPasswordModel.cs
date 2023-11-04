using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.Design.Serialization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class ResetPasswordModel
    { 
        public string HashCode { get; set; }

        [Required(ErrorMessage ="Необхідно ввести пароль.")]
        [StringLength(100, ErrorMessage = "Пароль повинен бути щонайменше {2} знаків у довжину.", MinimumLength = 8)]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Required(ErrorMessage = "Необхідно ввести підтвердження паролю.")]
        [Compare("Password", ErrorMessage = "Паролі не співпадають.")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
