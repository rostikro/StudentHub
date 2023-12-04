using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace SoftServeProject3.Core.DTOs;

public class EmailDataModel
{
    [Required(ErrorMessage ="Необхідно ввести пошту.")]
    [EmailValidation]
    public string EmailTo { get; set; }
}
