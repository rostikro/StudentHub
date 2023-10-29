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
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
        }
        public class registerRequest
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
        }
        public UsersController(IUserRepository userRepository, IJwtService jwtService)
        {
            _userRepository = userRepository;
            _jwtService = jwtService;
        }
        
        [HttpPost("login")]
        public IActionResult Login(LoginRequest loginRequest)
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

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, loginRequest.Email),
                // Треба додати username
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var token = _jwtService.GenerateJwtToken(claims);
            return Ok(new { Token = token });
        }
        [HttpGet("{email}")]
        public async Task<IActionResult> GetSchedule(string email)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);


            if (user == null || user.Schedule == null)
            {
                return NotFound();
            }
            return Ok(user.Schedule);
        }

        [HttpPut("{email}/{dayOfWeek}")]
        public async Task<IActionResult> UpdateSchedule(string email, string dayOfWeek, [FromBody] List<TimeRange> updatedSchedule)
        {
            var user = await _userRepository.GetUserByEmailAsync(email);
            if (user == null)
            {
                return NotFound();
            }

            if (user.Schedule == null)
            {
                user.Schedule = new Dictionary<string, List<TimeRange>>();
            }

            if (!user.Schedule.ContainsKey(dayOfWeek))
            {
                user.Schedule[dayOfWeek] = new List<TimeRange>();
            }

            TimeZoneInfo utcZone = TimeZoneInfo.Utc;


            user.Schedule[dayOfWeek] = updatedSchedule.Select(tr => new TimeRange
            {
                Start = TimeZoneInfo.ConvertTimeToUtc(new DateTime(1, 1, 1, tr.Start.Hour, tr.Start.Minute, 0), utcZone),
                End = TimeZoneInfo.ConvertTimeToUtc(new DateTime(1, 1, 1, tr.End.Hour, tr.End.Minute, 0), utcZone)
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
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, registerRequest.Email),
                // Треба додати username
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var token = _jwtService.GenerateJwtToken(claims);
            return Ok(new { Token = token});
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
