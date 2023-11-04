using System.ComponentModel.DataAnnotations;

namespace SoftServeProject3.Api.Entities;

public class EmailData
{
    [EmailAddress]
    public string EmailTo { get; set; }
}