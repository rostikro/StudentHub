﻿using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Repositories;
using SoftServeProject3.Api.Utils;
using SoftServeProject3.Core.DTOs;
using System.Text.RegularExpressions;

namespace SoftServeProject3.Api.Controllers;

[ApiController]
[Route("[controller]")]
public class EmailController : ControllerBase
{
    private readonly IEmailService _emailService;
    private readonly IUserRepository _userRepository;
    private readonly IVerificationRepository _verRepository;

    public EmailController(IEmailService emailService, IUserRepository userRepository, IVerificationRepository verRepository)
    {
        _emailService = emailService;
        _userRepository = userRepository;
        _verRepository = verRepository;
    }

    [HttpPost]
    [Route("SendVerificationCode")]
    public async Task<IActionResult> SendVerificationCodeAsync(EmailData emailData)
    {
        try
        {
            //check if user exists in user database
            //if (!await _userRepository.IfUserExistsAsync(emailData.EmailTo))
            //{
            //    return BadRequest("User with the email does not exist.");
            //}

            var code = RandomGenerator.GenerateRandomCode();

            var result = await _emailService.SendEmailAsync(emailData, code);

            if (!result)
            {
                return BadRequest("Failed to send verification code.");
            }

            var user = _userRepository.GetByEmail(emailData.EmailTo);

            var existingVerification = _verRepository.GetByEmail(emailData.EmailTo);
            //setting data for verification -> database
            var setData = new ForgotPasswordModel
            {
                Email = emailData.EmailTo,
                Code = code,
                ExpirationTime = DateTime.UtcNow.AddMinutes(10)
            };

            // check if user can send a code to his email now

            //changing user code if they exist in verification database + adding resend time 
            if (existingVerification != null)
            {
                if (_verRepository.GetByEmail(emailData.EmailTo).ResendCode < DateTime.UtcNow)
                {

                    await _verRepository.UpdateCodeAsync(setData);

                    return Ok("Verification code changed.");
                }

                else
                {
                    //telling user to wait to resend a code
                    return BadRequest($"You can resend code in " +
                        $"{Math.Round((_verRepository.GetByEmail(emailData.EmailTo).ResendCode - DateTime.UtcNow).TotalSeconds)} seconds.");
                }
            }
            else
            {

                _verRepository.CreateVerification(setData);

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
    [Route(("VerifyCodeEmail"))]
    public async Task<IActionResult> VerifyCodeAsync([FromBody] EmailData emailData, [FromQuery] string code)
    {
        try
        {
            var verification = _verRepository.GetByEmail(emailData.EmailTo);
            if (code != verification.Code)
            {
                return BadRequest("Code is not correct.");
            }
            //checking if the code is still valid
            if (verification.ExpirationTime < DateTime.UtcNow)
            {
                return BadRequest("Code has expired.");
            }

            //changing user email data to verified and removing user verification
            await _userRepository.UpdateUserAsync(emailData.EmailTo);
            var result = _verRepository.RemoveVerification(emailData.EmailTo);

            if (!result)
            {
                return BadRequest("Can't delete user verification.");
            }

            return Ok("Account verified successfully");
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            return BadRequest("VerifyCode | Internal Error:" + e.Message);
        }
    }

}