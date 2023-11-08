using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces;

public interface IEmailService
{
    Task<bool> SendVerificationEmailAsync(EmailData emailData, string verificationCode);
    Task<bool> SendResetPasswordEmailAsync(EmailData emailData, string verificationCode);
}