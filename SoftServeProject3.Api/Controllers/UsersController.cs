using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Interfaces;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;
using SoftServeProject3.Api.Utils;
using Newtonsoft.Json;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authorization;
using SoftServeProject3.Core.DTOs;
using MongoDB.Driver;


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
        /// Автентифікація користувача на основі його імені користувача/електронної пошти та пароля.
        /// </summary>
        /// <param name="loginRequest">Запит на вхід.</param>
        /// <returns>Токен JWT, якщо автентифікація пройшла успішно; в іншому випадку, повідомлення про помилку.</returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginModel loginModel)
        {
            
            var userInDb = loginModel.EmailorUsername.Contains("@") ? 
                await _userRepository.GetUserByEmailAsync(loginModel.EmailorUsername) :
                await _userRepository.GetUserByUsernameAsync(loginModel.EmailorUsername);

            if (userInDb == null ||
                userInDb != null && !BCrypt.Net.BCrypt.Verify(loginModel.Password, userInDb.Password))
            {
                return BadRequest("Неправильний логін або пароль.");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, userInDb.Email),
                new Claim(ClaimTypes.Name, userInDb.Username)
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

                var existingUser = await _userRepository.GetUserByUsernameAsync(profile.username);
                if (existingUser != null && existingUser.Email != email)
                {
                    return BadRequest("Username is already takennn.");
                }

                await _userRepository.UpdateProfileAsync(profile, email);

                return Ok("Success");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }


        [HttpGet("friends")]
        [Authorize]
        public async Task<IActionResult> GetFriendsAsync(string? username = null)
        {
            try
            {
                List<Friend> friends;

                if (string.IsNullOrEmpty(username))
                {
                    string email = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Email;
                    friends = await _userRepository.GetFriendsAsync(email);
                }
                else
                {
                    var user = await _userRepository.GetUserByUsernameAsync(username);
                    if (user == null)
                    {
                        return NotFound("User not found");
                    }
                    friends = await _userRepository.GetFriendsAsync(user.Email);
                }

                return Ok(friends);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpGet("friends/incomingRequests")]
        public async Task<IActionResult> GetIncomingFriendRequestsAsync(string token)
        {
            try
            {
                string email = _jwtService.DecodeJwtToken(token).Email;

                var incomingFriendRequests = await _userRepository.GetIncomingFriendRequestsAsync(email);

                return Ok(incomingFriendRequests);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpGet("friends/outgoingRequests")]
        public async Task<IActionResult> GetOutgoingFriendRequestsAsync(string token)
        {
            try
            {
                string email = _jwtService.DecodeJwtToken(token).Email;

                var outgoingFriendRequests = await _userRepository.GetOutgoingFriendRequestsAsync(email);

                return Ok(outgoingFriendRequests);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpPost("addFriend")]
        public async Task<IActionResult> AddFriendAsync(string token, string target)
        {
            try
            {
                string senderUsername = _jwtService.DecodeJwtToken(token).Username;

                await _userRepository.AddFriendRequest(senderUsername, target);

                return Ok("Success");
            }
            catch (KeyNotFoundException e)
            {
                Console.WriteLine(e);
                return NotFound(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpPost("cancelFriendRequest")]
        public async Task<IActionResult> CancelFriendRequestAsync(string token, string target)
        {
            try
            {
                string senderUsername = _jwtService.DecodeJwtToken(token).Username;

                await _userRepository.RemoveFriendRequest(senderUsername, target);

                return Ok("Success");
            }
            catch (KeyNotFoundException e)
            {
                Console.WriteLine(e);
                return NotFound(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpPost("ignoreFriendRequest")]
        public async Task<IActionResult> IgnoreFriendRequestAsync(string token, string target)
        {
            try
            {
                await _userRepository.RemoveFriendRequest(target, _jwtService.DecodeJwtToken(token).Username);

                return Ok("Success");
            }
            catch (KeyNotFoundException e)
            {
                Console.WriteLine(e);
                return NotFound(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpPost("acceptFriendRequest")]
        public async Task<IActionResult> AcceptFriendRequestAsync(string token, string target)
        {
            try
            {
                string senderUsername = _jwtService.DecodeJwtToken(token).Username;

                await _userRepository.AddFriend(senderUsername, target);

                return Ok("Success");
            }
            catch (KeyNotFoundException e)
            {
                Console.WriteLine(e);
                return NotFound(e.Message);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return BadRequest("Internal error");
            }
        }

        [HttpPost("removeFriend")]
        public async Task<IActionResult> RemoveFriendAsync(string token, string target)
        {
            try
            {
                string senderUsername = _jwtService.DecodeJwtToken(token).Username;

                await _userRepository.RemoveFriend(senderUsername, target);

                return Ok("Success");
            }
            catch (KeyNotFoundException e)
            {
                Console.WriteLine(e);
                return NotFound(e.Message);
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
        [Authorize]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userRepository.GetAllUsersAsync();

            var userSummaries = users.Where(u => !u.IsProfilePrivate)
                                     .Select(u => new UserListModel
                                     {
                                         Username = u.Username,
                                         Subjects = u.Subjects,
                                         Faculty = u.Faculty
                                     }).ToList();

            return Ok(userSummaries);
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
        [HttpGet("faculties")]
        public IActionResult GetFaculties()
        {
            var filePath = Path.Combine(_env.ContentRootPath, "Data", "Faculties.json");
            var jsonString = System.IO.File.ReadAllText(filePath);
            var faculties = JsonConvert.DeserializeObject<List<string>>(jsonString);

            return Ok(faculties);
        }
        /// <summary>
        /// Пошук користувачів за часовим інтервалом або/та списком предметів.
        /// </summary>
        /// <param name="startTime">Початковий час інтервалу.</param>
        /// <param name="endTime">Кінцевий час інтервалу.</param>
        /// <param name="subjects">Список предметів для фільтрації.</param>
        /// <returns>Фільтрований список користувачів.</returns>
        [HttpGet("search")]
        public async Task<IActionResult> SearchUsers(
        TimeSpan? startTime,
        TimeSpan? endTime,
        [FromQuery] List<string> subjects,
        [FromQuery] string faculty,
        [FromQuery] List<string> days)
        {
            var allUsers = await _userRepository.GetAllUsersAsync();
            var filteredUsers = allUsers.Where(u => !u.IsProfilePrivate).AsEnumerable();

            if (subjects != null && subjects.Any())
            {
                filteredUsers = filteredUsers.Where(u => u.Subjects != null && u.Subjects.Intersect(subjects, StringComparer.OrdinalIgnoreCase).Any());
            }
            if (!string.IsNullOrEmpty(faculty) && faculty != "Пусто")
            {
                filteredUsers = filteredUsers.Where(u => u.Faculty != null && u.Faculty.Equals(faculty, StringComparison.OrdinalIgnoreCase));
            }
            if (startTime.HasValue && endTime.HasValue)
            {
                filteredUsers = filteredUsers
                    .Select(u => new
                    {
                        User = u,
                        MatchingTimeRanges = u.Schedule
                            .Where(sch => days.Count == 0 || days.Contains(sch.Key)) 
                            .SelectMany(sch => sch.Value)
                            .Count(tr => (tr.Start.TimeOfDay <= startTime.Value && tr.End.TimeOfDay > startTime.Value) ||
                                         (tr.Start.TimeOfDay < endTime.Value && tr.End.TimeOfDay >= endTime.Value) ||
                                         (startTime.Value <= tr.Start.TimeOfDay && endTime.Value >= tr.End.TimeOfDay))
                    })
                    .Where(x => x.MatchingTimeRanges > 0)
                    .OrderByDescending(x => x.MatchingTimeRanges)
                    .Select(x => x.User);
            }

            if (!filteredUsers.Any())
                return NotFound("No users found matching the criteria.");

            return Ok(filteredUsers);
        }



        /// <summary>
        /// Реєстрація нового користувача.
        /// </summary>
        /// <param name="registerRequest">Запит на реєстрацію.</param>
        /// <returns>Токен JWT, якщо реєстрація пройшла успішно; в іншому випадку, повідомлення про помилку.</returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserModel registerRequest)
        {
            if (!registerRequest.IsEmailConfirmed)
            {
                if (string.IsNullOrWhiteSpace(registerRequest.Email)
                                || string.IsNullOrWhiteSpace(registerRequest.Password)
                                || string.IsNullOrWhiteSpace(registerRequest.Username))
                {
                    return BadRequest("Будь ласка, введіть нікнейм, пошту та пароль.");
                }
                else if (await _userRepository.GetUserByEmailAsync(registerRequest.Email) != null)
                {
                    return BadRequest("Користувач з такою поштою вже існує. Спробуйте іншу.");
                }
                else if (await _userRepository.GetUserByUsernameAsync(registerRequest.Username) != null)
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
        [HttpPost("login/google")]
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
            var userInDb = await _userRepository.GetUserByEmailAsync(userEmail);

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
                    Password = BCrypt.Net.BCrypt.HashPassword(KeyGenerator.GenerateRandomKey()),
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
                    },
                    Friends = new List<MongoDB.Bson.ObjectId>(),
                    OutgoingFriendRequests = new List<MongoDB.Bson.ObjectId>(),
                    IncomingFriendRequests = new List<MongoDB.Bson.ObjectId>(),
                    IsProfilePrivate = false,
                    IsFriendsPrivate = false,
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
            var existingUser = await _userRepository.GetUserByEmailAsync(verification.Email);

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