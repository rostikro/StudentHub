using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Interfaces;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using SoftServeProject3.Api.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authorization;
using SoftServeProject3.Core.DTOs;
using MongoDB.Driver;
using SoftServeProject3.Api.Repositories;

namespace SoftServeProject3.Api.Controllers
{
    /// <summary>
    /// Контролер для управління операціями користувача, такими як автентифікація, реєстрація та управління розкладом.
    /// </summary>
    [ApiController]
    [Route("[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly IVerificationRepository _verRepository;
        private readonly IJwtService _jwtService;
        private readonly IWebHostEnvironment _env;



        /// <summary>
        /// Ініціалізує новий екземпляр класу <see cref="UsersController"/>.
        /// </summary>
        /// <param name="userRepository">Репозиторій користувачів.</param>
        /// <param name="jwtService">Служба JWT.</param>
        /// <exception cref="ArgumentNullException">Викидається, коли userRepository або jwtService дорівнює null.</exception>
        public UsersController(IUserRepository userRepository, IJwtService jwtService, IWebHostEnvironment env, IVerificationRepository verRepository)
        {
            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _jwtService = jwtService ?? throw new ArgumentNullException(nameof(jwtService));
            _env = env;
            _verRepository = verRepository;
        }

        /// <summary>
        /// Представляє запит на вхід користувача в систему.
        /// </summary>
        public class LoginRequest
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string Password { get; set; }
        }

        /// <summary>
        /// Автентифікація користувача на основі його імені користувача/електронної пошти та пароля.
        /// </summary>
        /// <param name="loginRequest">Запит на вхід.</param>
        /// <returns>Токен JWT, якщо автентифікація пройшла успішно; в іншому випадку, повідомлення про помилку.</returns>
        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest loginRequest)
        {
            var userInDb = _userRepository.GetByEmail(loginRequest.Email) ?? _userRepository.GetByUsername(loginRequest.Username);

            if (userInDb == null)
            {
                return BadRequest("Invalid email or password.");
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

        /// <summary>
        /// Returns a json representation of user profile
        /// </summary>
        /// <param name="email">user email</param>
        [HttpGet("profile/{username?}")]
        [Authorize]
        public async Task<IActionResult> GetProfileAsync(string username = null)
        {
            try
            {
                UserModel user;

                if (username == null)
                {
                    string emailToken = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Email;
                    string userToken = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Username;

                    user = await _userRepository.GetUserByEmailAsync(emailToken) ?? await _userRepository.GetUserByUsernameAsync(userToken);
                    if (user == null)
                    {
                        return BadRequest("Invalid email/username");
                    }
                }
                else
                {
                    user = await _userRepository.GetUserByUsernameAsync(username);
                }

                var serializeOptions = new JsonSerializerSettings
                {
                    ContractResolver = new GetUserContractResolver(),
                };

                var jsonRepsonse = JsonConvert.SerializeObject(user, serializeOptions);

                return Ok(jsonRepsonse);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }


        [HttpPost("updateProfile")]
        [Authorize]
        public async Task<IActionResult> UpdateProfileAsync([FromBody] UpdateProfile profile)
        {
            try
            {
                string email = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Email;

                await _userRepository.UpdateProfileAsync(profile, email);

                return Ok("Success");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        /// <summary>
        /// Отримує список всіх користувачів.
        /// </summary>
        /// <returns>Список користувачів.</returns>
        [HttpGet("list")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userRepository.GetAllUsersAsync();
            return Ok(users);
        }

        /// <summary>
        /// Отримує список предметів з JSON-файлу.
        /// </summary>
        /// <returns>Список предметів.</returns>
        [HttpGet("subjects")]
        public IActionResult Get()
        {
            var filePath = Path.Combine(_env.ContentRootPath, "Data", "Subjects.json");
            var jsonString = System.IO.File.ReadAllText(filePath);
            var subjects = JsonConvert.DeserializeObject<List<string>>(jsonString);

            return Ok(subjects);
        }

        /// <summary>
        /// Пошук користувачів за часовим інтервалом або/та списком предметів.
        /// </summary>
        /// <param name="startTime">Початковий час інтервалу.</param>
        /// <param name="endTime">Кінцевий час інтервалу.</param>
        /// <param name="subjects">Список предметів для фільтрації.</param>
        /// <returns>Фільтрований список користувачів.</returns>
        [HttpGet("search")]
        public async Task<IActionResult> SearchUsers(TimeSpan? startTime, TimeSpan? endTime, [FromQuery] List<string> subjects)
        {
            var allUsers = await _userRepository.GetAllUsersAsync();
            var filteredUsers = allUsers.AsEnumerable();

            if (startTime.HasValue && endTime.HasValue)
            {
                filteredUsers = filteredUsers.Where(u => u.Schedule != null && u.Schedule.Any(day =>
                        day.Value.Any(timeRange =>
                            (timeRange.Start.TimeOfDay <= startTime.Value && timeRange.End.TimeOfDay > startTime.Value) ||
                            (timeRange.Start.TimeOfDay < endTime.Value && timeRange.End.TimeOfDay >= endTime.Value) ||
                            (startTime.Value <= timeRange.Start.TimeOfDay && endTime.Value >= timeRange.End.TimeOfDay)))).ToList();
            }

            if (subjects != null && subjects.Any())
            {
                filteredUsers = filteredUsers.Where(u => u.Subjects != null && u.Subjects.Intersect(subjects, StringComparer.OrdinalIgnoreCase).Any()).ToList();
            }

            if (!filteredUsers.Any())
                return NotFound("No users");

            return Ok(filteredUsers);
        }



        /// <summary>
        /// Реєстрація нового користувача.
        /// </summary>
        /// <param name="registerRequest">Запит на реєстрацію.</param>
        /// <returns>Токен JWT, якщо реєстрація пройшла успішно; в іншому випадку, повідомлення про помилку.</returns>
        [HttpPost("register")]
        public IActionResult Register([FromBody] UserModel registerRequest)
        {
            if (!registerRequest.IsEmailConfirmed)
            {
                if (string.IsNullOrWhiteSpace(registerRequest.Email)
                                || string.IsNullOrWhiteSpace(registerRequest.Password)
                                || string.IsNullOrWhiteSpace(registerRequest.Username))
                {
                    return BadRequest("Будь ласка, введіть нікнейм, пошту та пароль.");
                }
                else if (_userRepository.GetByEmail(registerRequest.Email) != null)
                {
                    return BadRequest("Користувач з такою поштою вже існує. Спробуйте іншу.");
                }
                else if (_userRepository.GetByUsername(registerRequest.Username) != null)
                {
                    return BadRequest("Користувач з таким юзернеймом вже існує. Спробуйте інший.");
                }
                else
                {
                    return Ok("");
                }
            }
            else
            {
                _userRepository.Register(registerRequest);

                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, registerRequest.Email),
                new Claim(ClaimTypes.Name, registerRequest.Username)
            };

                var token = _jwtService.GenerateJwtToken(claims);
                return Ok(new { Token = token });
            }



        }

        /// <summary>
        /// Ініціація процесу входу в систему Google OAuth.
        /// </summary>
        /// <returns>Результат виклику, який перенаправляє на Google для аутентифікації.</returns>
        [HttpGet("login/google")]
        public IActionResult GoogleLogin()
        {
            var authenticationProperties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("GoogleResponse")
            };
            return Challenge(authenticationProperties, "Google");
        }

        /// <summary>
        /// Обробка відповіді від Google OAuth та завершення процесу аутентифікації.
        /// </summary>
        /// <returns>Результат перенаправлення з токеном JWT, якщо аутентифікація пройшла успішно; в іншому випадку, повідомлення про помилку.</returns>
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
                var newUser = new UserModel
                {
                    Username = $"user-{RandomGenerator.GenerateRandomCode()}",
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
                    },
                    PhotoUrl = "",
                    Faculty = "",
                    Name = "",
                    Description = "",
                    Subjects = new List<string>(),
                    Social = new Dictionary<string, string>
                    {
                        { "instagram", "" },
                        { "twitter", "" },
                        { "github", "" },
                        { "facebook", "" },
                        { "telegram", "" }
                    }
                };

                _userRepository.Register(newUser);
                var RegToken = _jwtService.GenerateJwtToken(claims);
                return Redirect($"https://localhost:7182/login?token={RegToken}");
            }

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

            if (!BCrypt.Net.BCrypt.Verify(verification.Code, resetPassword.HashCode))
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
                await _userRepository.UpdateUserPasswordAsync(existingUser, BCrypt.Net.BCrypt.HashPassword(resetPassword.Password));
                //existingUser.Password = resetPassword.Password;
                return Ok(new { Message = "Password has been changed successfully." });
            }
        }
    }
}