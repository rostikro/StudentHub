using MongoDB.Driver;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;

namespace SoftServeProject3.Api.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly IMongoCollection<UserModel> _users;

        public UserRepository(string connectionString)
        {

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");

            _users = database.GetCollection<UserModel>("users");
        }

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

        public async Task UpdateUserAsync(string email)
        {
            try
            {
                await _users.UpdateOneAsync(user => user.Email == email,
                    Builders<UserModel>.Update.Set(user => user.IsEmailConfirmed, true));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public UserModel GetByEmail(string email)
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
        public UserModel GetByUsername(string username)
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
        public void Register(UserModel user)
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

    }
}

