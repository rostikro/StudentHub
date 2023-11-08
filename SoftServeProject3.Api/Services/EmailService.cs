using System.Text.Json.Serialization;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
using Newtonsoft.Json;
using SoftServeProject3.Api.Configurations;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;

namespace SoftServeProject3.Api.Services;

public class EmailService : IEmailService
{
    private readonly EmailSettings _emailSettings;
    private readonly HttpClient _httpClient;
    
    public EmailService(IOptions<EmailSettings> emailSettingsOptions, IHttpClientFactory httpClientFactory)
    {
        _emailSettings = emailSettingsOptions.Value;
        _httpClient = httpClientFactory.CreateClient("EmailClient");
    }

    public async Task<bool> SendVerificationEmailAsync(EmailData emailData, string verificationCode)
    {
        return await SendEmailAsync(emailData, verificationCode, "8131879a-6a70-42eb-9ba3-c35a43236733");
    }
    
    
    public async Task<bool> SendResetPasswordEmailAsync(EmailData emailData, string verificationCode)
    {
        return await SendEmailAsync(emailData, verificationCode, "2b807789-0755-4c96-a6b5-d291bb23ea25");
    }

    private async Task<bool> SendEmailAsync(EmailData emailData, string verificationCode, string template_uuid)
    {
        try
        {
            var apiEmail = new
            {
                From = new { Email = _emailSettings.SenderEmail, Name = _emailSettings.SenderName },
                To = new[] { new { Email = emailData.EmailTo, Name = emailData.EmailTo } },
                Template_uuid = template_uuid,
                Template_variables = new { verification_code = verificationCode }
            };

            var httpResponse = await _httpClient.PostAsJsonAsync("send", apiEmail);
            var responseJson = await httpResponse.Content.ReadAsStringAsync();
            var response = JsonConvert.DeserializeObject<Dictionary<string, object>>(responseJson);

            if (response != null && response.TryGetValue("success", out object? success) &&
                success is bool boolSuccess &&
                boolSuccess)
            {
                return true;
            }
            
            Console.WriteLine(responseJson);
            return false;
        }
        catch (Exception e)
        {
            Console.WriteLine("Email error | SendEmailAsync(): " + e);
            return false;
        }
    }
}