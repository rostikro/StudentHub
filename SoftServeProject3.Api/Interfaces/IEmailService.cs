using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces;

public interface IEmailService
{
    Task<bool> SendEmailAsync(EmailData emailData, string verificationCode);
}