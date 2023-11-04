using System.ComponentModel.DataAnnotations;

namespace SoftServeProject3.Core.DTOs;

public class EmailDataModel
{
    [Required(ErrorMessage ="Необхідно ввести пошту.")]
    [EmailAddress(ErrorMessage ="")]
    public string EmailTo { get; set; }
}