﻿using Microsoft.AspNetCore.Mvc;
using Org.BouncyCastle.Ocsp;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Repositories;
using SoftServeProject3.Api.Utils;
using SoftServeProject3.Core.DTOs;
using System.Reflection.Emit;
using System.Text.RegularExpressions;

namespace SoftServeProject3.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class EmailController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly IUserRepository _userRepository;
    private readonly IVerificationRepository _verRepository;

    //private static IDictionary<string, string> _codes = new Dictionary<string, string>();
    public EmailController(IEmailService emailService, IUserRepository userRepository, IVerificationRepository verRepository)
    {
        _emailService = emailService;
        _userRepository = userRepository;
        _verRepository = verRepository;
    }

    [HttpPost]
    [Route("SendVerificationCodePassword")]
    public async Task<IActionResult> SendVerificationCodePasswordAsync(EmailData emailData, [FromQuery] bool isReset = false)
    {
        try
        {
            //check if user exists in user database
            if (isReset)
            {
                if (!await _userRepository.IsUserExistsAsync(emailData.EmailTo))
                {
                    return BadRequest("Користувач з такою поштою не існує.");
                }
            }


            await _verRepository.ClearVerifications();

            var code = RandomGenerator.GenerateRandomCode();

            var existingVerification = await _verRepository.GetByEmail(emailData.EmailTo);

            //setting data for verification -> database
            var setData = new ForgotPasswordModel
            {
                Email = emailData.EmailTo,
                Code = code
            };

            //changing user code if they exist in verification database + adding resend time 
            if (existingVerification != null)
            {
                // check if user can send a code to his email now
                if ((await _verRepository.GetByEmail(emailData.EmailTo)).ResendCode < DateTime.Now)
                {
                    bool result;

                    if (isReset)
                    {
                        result = await _emailService.SendResetPasswordEmailAsync(emailData, code);
                    }
                    else
                    {
                        result = await _emailService.SendVerificationEmailAsync(emailData, code);
                    }


                    if (!result)
                    {
                        return BadRequest("Сталася помилка при відсиланні коду:( Спробуйте ще раз.");
                    }

                    await _verRepository.UpdateCodeAsync(setData);

                    return Ok("Verification code changed.");
                }

                else
                {
                    //telling user to wait to resend a code
                    return BadRequest($"Зачекайте, будь ласка. Код можна відіслати ще раз через " +
                        $"{Math.Round(((await _verRepository.GetByEmail(emailData.EmailTo)).ResendCode - DateTime.Now).TotalSeconds)} секунд.");
                }
            }
            else
            {

                await _verRepository.CreateVerification(setData);

                return Ok("Verification code has been set to user.");
            }

        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return BadRequest("SendVerificationCode | Internal Error:" + e.Message);
        }

    }

    [HttpPost]
    [Route("VerifyCodeEmail")]
    public async Task<IActionResult> VerifyCodeAsync(ForgotPasswordModel verData)
    {
        try
        {
            var verification = await _verRepository.GetByEmail(verData.Email);

            if (verData.Code != verification.Code)
            {
                return BadRequest("Неправильний код.");
            }
            //checking if the code is still valid
            if (verification.ExpirationTime < DateTime.UtcNow)
            {
                return BadRequest("Термін дії коду закінчився.Спробуйте відправити новий.");
            }

            //changing user email data to verified and removing user verification
            await _userRepository.UpdateUserAsync(verData.Email);

            return Ok("Account verified successfully");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return BadRequest("VerifyCode | Internal Error:" + e.Message);
        }
    }
}