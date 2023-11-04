using System.ComponentModel.DataAnnotations;

namespace SoftServeProject3.Api.Configurations;

public class EmailSettings
{
    public string SenderName { get; set; }

    [EmailAddress]
    public string SenderEmail { get; set; }

    public string ApiToken { get; set; }

    public string ApiBaseUrl { get; set; }
}