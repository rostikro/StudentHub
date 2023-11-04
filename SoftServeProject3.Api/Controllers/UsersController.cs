using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authorization;
using SoftServeProject3.Core.DTOs;
using MongoDB.Driver;

namespace SoftServeProject3.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {

        private readonly IUserRepository _userRepository;
        private readonly IVerificationRepository _verRepository;
        private readonly IJwtService _jwtService;

        public UsersController(IUserRepository userRepository, IJwtService jwtService, IVerificationRepository verRepository)
        {
            _userRepository = userRepository;
            _jwtService = jwtService;
            _verRepository = verRepository;
        }

        [HttpPost("login")]
        public IActionResult Login(UserModel loginRequest)
        {
            var userInDb = _userRepository.GetByEmail(loginRequest.Email);

            if (userInDb == null)
            {
                return BadRequest("Invalid email or password.");
            }

            bool isPasswordValid = BCrypt.Net.BCrypt.Verify(loginRequest.Password, userInDb.Password);

            if (!isPasswordValid)
            {
                return BadRequest("Invalid email or password.");
            }



            return Ok(new { Message = "Logged in successfully." });
        }
        [HttpPost("register")]
        public IActionResult Register(UserModel registerRequest)
        {
            if (string.IsNullOrEmpty(registerRequest.Email) || string.IsNullOrEmpty(registerRequest.Password))
            {
                return BadRequest("Email and Password are required.");
            }


            var existingUser = _userRepository.GetByEmail(registerRequest.Email);
            if (existingUser != null)
            {
                return BadRequest("Email already exists.");
            }


            _userRepository.Register(registerRequest);

            return Ok(new { Message = "Registration successful." });
        }
        [HttpGet("login/google")]
        public IActionResult GoogleLogin()
        {
            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse")
            };
            return Challenge(authenticationProperties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("auth/google/callback")]
        public async Task<IActionResult> GoogleResponse()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (!authenticateResult.Succeeded)
            {
                return BadRequest("Error authenticating with Google");
            }


            var emailClaim = authenticateResult.Principal.FindFirst(ClaimTypes.Email);
            //gets user's name from Google
            var nameClaim = authenticateResult.Principal.FindFirst(ClaimTypes.Name);

            //gets user's name from Google
            //var nameClaim = authenticateResult.Principal.FindFirst(ClaimTypes.Name);

            //gets user's name from Google
            //var nameClaim = authenticateResult.Principal.FindFirst(ClaimTypes.Name);

            if (emailClaim == null)
            {
                return BadRequest("No email claim found");
            }

            var userEmail = emailClaim.Value;
            var userInDb = _userRepository.GetByEmail(userEmail);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, userEmail),

            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

            if (userInDb == null)
            {

                var newUser = new UserModel
                {
                    Email = userEmail,
                    Password = KeyGenerator.GenerateRandomKey(64),
                    IsEmailConfirmed = true
                };
                Console.WriteLine("NoUser");
                _userRepository.Register(newUser);

                var RegToken = _jwtService.GenerateJwtToken(claims);
                return Redirect($"https://localhost:7182/login?token={RegToken}");
            }
            


            
            // Generate JWT token

            var token = _jwtService.GenerateJwtToken(claims);
            return Redirect($"https://localhost:7182/login?token={token}");

        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPassword)
        {
            if (resetPassword.Password != resetPassword.ConfirmPassword)
                return BadRequest("Паролі не співпадають.");


            var verification = _verRepository.GetByHashCode(resetPassword.HashCode).Result;

            //перевірки клієнта
            if (verification == null)
                return BadRequest("Користувача не знайдено.");
            
            if(!BCrypt.Net.BCrypt.Verify(verification.Code, resetPassword.HashCode))
                return BadRequest("Щось пішло не так : (");

            if (verification.ExpirationTime < DateTime.UtcNow)
                return BadRequest("Час на зміну пароля сплив. Спробуйте відіслати код ще раз.");

            //зміна паролю
            var existingUser = _userRepository.GetByEmail(verification.Email);

            var result = _verRepository.RemoveVerification(verification.Email);

            if (!result)
            {
                return BadRequest("Can't delete user verification.");
            }

            if (existingUser == null)
                return BadRequest("Неможливо знайти користувача : (");
            else
            {
                existingUser.Password = resetPassword.Password;
                return Ok(new { Message = "Password has been changed successfully." });
            }
        }

        //Playground

    }
}
