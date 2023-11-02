using MongoDB.Driver;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;

namespace SoftServeProject3.Api.Repositories
{
    /// <summary>
    /// Реалізація інтерфейсу репозиторію користувача для роботи з базою даних MongoDB.
    /// </summary>
    public class UserRepository : IUserRepository
    {
        private readonly IMongoCollection<User> _users;

        /// <summary>
        /// Ініціалізує новий екземпляр класу <see cref="UserRepository"/>.
        /// </summary>
        /// <param name="connectionString">string підключення до MongoDB.</param>
        public UserRepository(string connectionString)
        {

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");

            _users = database.GetCollection<User>("users");
        }

        /// <summary>
        /// Перевіряє, чи існує користувач з вказаною електронною поштою в базі даних.
        /// </summary>
        /// <param name="email">Електронна пошта для пошуку користувача.</param>
        /// <returns>Повертає <c>true</c>, якщо користувач існує; в іншому випадку, <c>false</c>.</returns>
        public async Task<bool> IsUserExistsAsync(string email)
        {
            try
            {
                var user = await _users.Find(user => user.Email == email).FirstOrDefaultAsync();

                return user != null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        /// <summary>
        /// Оновлює статус підтвердження електронної пошти користувача.
        /// </summary>
        /// <param name="email">Електронна пошта користувача.</param>
        /// <returns>Асинхронна задача.</returns>
        public async Task UpdateUserAsync(string email)
        {
            try
            {
                await _users.UpdateOneAsync(user => user.Email == email,
                    Builders<User>.Update.Set(user => user.IsEmailConfirmed, true));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        /// <summary>
        /// Замінює існуючий об'єкт користувача в базі даних на новий.
        /// </summary>
        /// <param name="user">Новий об'єкт користувача.</param>
        /// <returns>Асинхронна задача.</returns>
        public async Task UpdateUserAsync(User user)
        {
            await _users.ReplaceOneAsync(u => u.Email == user.Email, user);
        }

        /// <summary>
        /// Отримує об'єкт користувача за його електронною поштою.
        /// </summary>
        /// <param name="email">Електронна пошта користувача.</param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public User GetByEmail(string email)
        {
            try
            {


                var user = _users.Find(user => user.Email == email).FirstOrDefault();

                if (user == null)
                {
                    Console.WriteLine($"No user found with email: {email}");
                }
                else
                {
                    Console.WriteLine($"User found with email: {user.Email}");
                }

                return user;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user by email: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Отримує об'єкт користувача за його іменем користувача.
        /// </summary>
        /// <param name="username">Ім'я користувача.</param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public User GetByUsername(string username)
        {
            try
            {


                var user = _users.Find(user => user.Username == username).FirstOrDefault();

                if (user == null)
                {
                    Console.WriteLine($"No user found with username: {username}");
                }
                else
                {
                    Console.WriteLine($"User found with username: {user.Username}");
                }

                return user;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user by username: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Реєструє нового користувача в системі.
        /// </summary>
        /// <param name="user">Об'єкт користувача для реєстрації.</param>
        public void Register(User user)
        {
            try
            {
                
                user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
                _users.InsertOne(user);
                Console.WriteLine($"User registered with email: {user.Email}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registering user: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Отримує об'єкт користувача за його електронною поштою асинхронно.
        /// </summary>
        /// <param name="email">Електронна пошта користувача.</param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public async Task<User> GetUserByEmailAsync(string email)
        {
            return await _users.Find(u => u.Email == email).FirstOrDefaultAsync();
        }

        /// <summary>
        /// Отримує об'єкт користувача за його іменем користувача асинхронно.
        /// </summary>
        /// <param name="username">Ім'я користувача. </param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public async Task<User> GetUserByUsernameAsync(string username)
        {
            return await _users.Find(u => u.Username == username).FirstOrDefaultAsync();
        }
    }
}


