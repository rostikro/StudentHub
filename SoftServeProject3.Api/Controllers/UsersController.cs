using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authorization;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {

        private readonly IUserRepository _userRepository;
        private readonly IJwtService _jwtService;

        public UsersController(IUserRepository userRepository, IJwtService jwtService)
        {
            _userRepository = userRepository;
            _jwtService = jwtService;
        }
        // Добавить токен
        [HttpPost("login")]
        public IActionResult Login(User loginRequest)
        {
            var userInDb = _userRepository.GetByEmail(loginRequest.Email);
            var userInDb2 = _userRepository.GetByUsername(loginRequest.Username);
            
            if (userInDb == null && userInDb2 == null)
            {
                return BadRequest("Invalid email/username");
            }
            
            bool isPasswordValid = userInDb == null ? BCrypt.Net.BCrypt.Verify(loginRequest.Password, userInDb2.Password) : BCrypt.Net.BCrypt.Verify(loginRequest.Password, userInDb.Password);
            

            if (!isPasswordValid)
            {
                return BadRequest("Invalid password.");
            }



            return Ok(new { Message = "Logged in successfully." });
        }
        // Добавить токен
        [HttpPost("register")]
        public IActionResult Register(User registerRequest)
        {
            if (string.IsNullOrEmpty(registerRequest.Email) || string.IsNullOrEmpty(registerRequest.Password) || string.IsNullOrEmpty(registerRequest.Username))
            {
                return BadRequest("Email, UserName and Password are required.");
            }


            var existingEmail = _userRepository.GetByEmail(registerRequest.Email);
            var existingUsername = _userRepository.GetByUsername(registerRequest.Username);
            
            if (existingEmail != null)
            {
                return BadRequest("Email already exists.");
            }
            else if(existingUsername != null)
            {
                return BadRequest("Username already exists.");
            }

            _userRepository.Register(registerRequest);

            return Ok(new { Message = "Registration successful." });
        }
        [HttpPost("set/newPassword")]
        public IActionResult SetNewPassword(SetPassword newPasswordRequest)
        {
            if (newPasswordRequest.Password != newPasswordRequest.ConfirmPassword)
            {
                return BadRequest("Passwords don't match.");
            }
            else if (newPasswordRequest.Password.Length < 8)
            {
                return BadRequest("Password should be at least 8 character long.");
            }
            else
            {
                return Ok();
            }

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

                var newUser = new User
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
    }
}
