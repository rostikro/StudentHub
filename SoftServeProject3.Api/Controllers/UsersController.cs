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
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
        }
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
        }
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            var userInDb = _userRepository.GetByEmail(loginRequest.Email) ?? _userRepository.GetByUsername(loginRequest.Username);

            if (userInDb == null)
            {
                return BadRequest("Invalid email/username");
            }

            if (!BCrypt.Net.BCrypt.Verify(loginRequest.Password, userInDb.Password))
            {
                return BadRequest("Invalid password.");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, loginRequest.Email),
                new Claim(ClaimTypes.Name, loginRequest.Username)
            };

            var token = _jwtService.GenerateJwtToken(claims);
            return Ok(new { Token = token });
        }

        [HttpGet("{email}")]
        public async Task<IActionResult> GetSchedule(string email)
        {
            
            var user = await _userRepository.GetUserByEmailAsync(email);
            var user2 = await _userRepository.GetUserByUsernameAsync(email);
            if (user?.Schedule == null && user2?.Schedule == null)
            {
                return NotFound();
            }
            if (user ==  null) 
            { 
                return Ok(user2.Schedule); 
            }
            else
            {
                return Ok(user.Schedule);
            }
            
            
        }

        [HttpPut("{email}/{dayOfWeek}")]
        public async Task<IActionResult> UpdateSchedule(string email, string dayOfWeek, [FromBody] List<TimeRange> updatedSchedule)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            user.Schedule ??= new Dictionary<string, List<TimeRange>>();
            user.Schedule[dayOfWeek] = updatedSchedule.Select(tr => new TimeRange
            {
                Start = DateTime.SpecifyKind(tr.Start, DateTimeKind.Utc),
                End = DateTime.SpecifyKind(tr.End, DateTimeKind.Utc)
            }).ToList();

            await _userRepository.UpdateUserAsync(user);
            return NoContent();
        }

        [HttpPost("get-user-info")]
        public ActionResult<UserInfo> GetUserInfo([FromBody] string token)
        {
            try
            {
                var userInfo = _jwtService.DecodeJwtToken(token);
                return Ok(userInfo);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [HttpPost("register")]
        public IActionResult Register([FromBody] User registerRequest)
        {
            if (string.IsNullOrWhiteSpace(registerRequest.Email) || string.IsNullOrWhiteSpace(registerRequest.Password) || string.IsNullOrWhiteSpace(registerRequest.Username))
            {
                return BadRequest("Email, UserName and Password are required.");
            }

            if (_userRepository.GetByEmail(registerRequest.Email) != null)
            {
                return BadRequest("Email already exists.");
            }

            if (_userRepository.GetByUsername(registerRequest.Username) != null)
            {
                return BadRequest("Username already exists.");
            }

            _userRepository.Register(registerRequest);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, registerRequest.Email),
                new Claim(ClaimTypes.Name, registerRequest.Username)
            };

            var token = _jwtService.GenerateJwtToken(claims);
            return Ok(new { Token = token });
        }

        [HttpGet("login/google")]
        public IActionResult GoogleLogin()
        {
            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse")
            };
            return Challenge(authenticationProperties, "Google");
        }

        [HttpGet("auth/google/callback")]
        public async Task<IActionResult> GoogleResponse()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync("Google");

            if (!authenticateResult.Succeeded)
            {
                return BadRequest("Error authenticating with Google");
            }

            var emailClaim = authenticateResult.Principal?.FindFirst(ClaimTypes.Email);
            if (emailClaim == null)
            {
                return BadRequest("No email claim found");
            }

            var userEmail = emailClaim.Value;
            var userInDb = _userRepository.GetByEmail(userEmail);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, userEmail),
                new Claim(ClaimTypes.Name, userEmail)
            };

            if (userInDb == null)
            {
                var newUser = new User
                {
                    Email = userEmail,
                    Password = BCrypt.Net.BCrypt.HashPassword(KeyGenerator.GenerateRandomKey(64)),
                    IsEmailConfirmed = true,
                    Schedule = new Dictionary<string, List<TimeRange>>
                    {
                        { "Monday", new List<TimeRange>() },
                        { "Tuesday", new List<TimeRange>() },
                        { "Wednesday", new List<TimeRange>() },
                        { "Thursday", new List<TimeRange>() },
                        { "Friday", new List<TimeRange>() },
                        { "Saturday", new List<TimeRange>() },
                        { "Sunday", new List<TimeRange>() },
                    }
                };

                _userRepository.Register(newUser);
                var RegToken = _jwtService.GenerateJwtToken(claims);
                return Redirect($"https://localhost:7182/login?token={RegToken}");
            }

            var token = _jwtService.GenerateJwtToken(claims);
            return Redirect($"https://localhost:7182/login?token={token}");
        }
    }
}