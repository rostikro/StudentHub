using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Repositories;
using SoftServeProject3.Api.Utils;

namespace SoftServeProject3.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class EmailController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly IUserRepository _userRepository;

    private static IDictionary<string, string> _codes = new Dictionary<string, string>();

    public EmailController(IEmailService emailService, IUserRepository userRepository)
    {
        _emailService = emailService;
        _userRepository = userRepository;
    }

    [HttpPost]
    [Route("SendVerificationCode")]
    public async Task<IActionResult> SendVerificationCodeAsync(EmailData emailData)
    {
        try
        {
            if (!await _userRepository.IsUserExistsAsync(emailData.EmailTo))
            {
                return BadRequest("User is not exists");
            }
            
            var code = RandomGenerator.GenerateRandomCode();

            var result = await _emailService.SendEmailAsync(emailData, code);

            if (!result)
            {
                return BadRequest("Failed to send verification code.");
            }
            
            _codes[emailData.EmailTo] = code;
            
            return Ok("Verification code succeeded.");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return BadRequest("SendVerificationCode | Internal Error:" + e.Message);
        }

    }

    [HttpPost]
    [Route(("VerifyCode"))]
    public async Task<IActionResult> VerifyCodeAsync([FromBody] EmailData emailData, [FromQuery] string code)
    {
        try
        {
            if (code != _codes[emailData.EmailTo])
            {
                return BadRequest("Code is not correct");
            }
            
            await _userRepository.UpdateUserAsync(emailData.EmailTo);
            _codes.Remove(emailData.EmailTo);

            return Ok("Account verified successfully");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return BadRequest("VerifyCode | Internal Error:" + e.Message);
        }
    }

}