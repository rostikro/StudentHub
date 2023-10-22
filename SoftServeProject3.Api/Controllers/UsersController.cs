using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authorization;


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

        [HttpPost("login")]
        public IActionResult Login(User loginRequest)
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
        public IActionResult Register(User registerRequest)
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
