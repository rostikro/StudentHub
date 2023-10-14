using MongoDB.Driver;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;

namespace SoftServeProject3.Api.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly IMongoCollection<User> _users;

        public UserRepository(string connectionString)
        {

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");

            _users = database.GetCollection<User>("users");
        }

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

    }
}


