using MongoDB.Bson;
using Microsoft.AspNetCore.Http.HttpResults;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Services;

namespace SoftServeProject3.Api.Repositories
{
    /// <summary>
    /// Реалізація інтерфейсу репозиторію користувача для роботи з базою даних MongoDB.
    /// </summary>
    public class UserRepository : IUserRepository
    {
        private readonly IMongoCollection<UserModel> _users;

        /// <summary>
        /// Ініціалізує новий екземпляр класу <see cref="UserRepository"/>.
        /// </summary>
        /// <param name="connectionString">string підключення до MongoDB.</param>
        public UserRepository(string connectionString)
        {

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");

            _users = database.GetCollection<UserModel>("users");
        }

        /// <summary>
        /// Updates user profile in database
        /// </summary>
        /// <param name="profile"></param>
        /// <param name="email"></param>
        public async Task UpdateProfileAsync(UpdateProfile profile, string email)
        {
            try
            {
                await _users.UpdateOneAsync(user => user.Email == email,
                    Builders<UserModel>.Update
                        
                        .Set(u => u.PhotoUrl, profile.photoUrl)
                        .Set(u => u.Faculty, profile.faculty)
                        .Set(u => u.Name, profile.name)
                        .Set(u => u.Description, profile.description)
                        .Set(u => u.Subjects, profile.subjects)
                        .Set(u => u.Social, profile.social)
                        .Set(u => u.Schedule, profile.schedule)
                        .Set(u => u.Username, profile.username)
                        .Set(u => u.IsProfilePrivate, profile.isprofileprivate)
                        .Set(u => u.IsFriendsPrivate, profile.isfriendsprivate)
                    );
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }
        
        private async Task<List<Friend>> GetFriendsMetaAsync(List<ObjectId> friendsIds)
        {
            var friendsFilter = Builders<UserModel>.Filter.In(u => u._id, friendsIds);
            var friendsProject = Builders<UserModel>.Projection
                .Include(u => u.Username)
                .Include(u => u.PhotoUrl)
                .Exclude(u => u._id);
                
            var friends = await _users.Find(friendsFilter).Project(friendsProject).ToListAsync();
                
            return friends.Select(f => BsonSerializer.Deserialize<Friend>(f)).ToList();
        }

        public async Task<List<Friend>> GetFriendsAsync(string email)
        {
            try
            {
                var friendsIds = await _users.Find(u => u.Email == email).Project(u => u.Friends).FirstOrDefaultAsync();

                return await GetFriendsMetaAsync(friendsIds);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task<List<Friend>> GetIncomingFriendRequestsAsync(string email)
        {
            try
            {
                var friendsIds = await _users.Find(u => u.Email == email).Project(u => u.IncomingFriendRequests).FirstOrDefaultAsync();

                return await GetFriendsMetaAsync(friendsIds);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task<List<Friend>> GetOutgoingFriendRequestsAsync(string email)
        {
            try
            {
                var friendsIds = await _users.Find(u => u.Email == email).Project(u => u.OutgoingFriendRequests).FirstOrDefaultAsync();

                return await GetFriendsMetaAsync(friendsIds);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task AddFriendRequest(string sender, string target)
        {
            try
            {
                var senderId = await GetUserIdAsync(sender);
                var targetId = await GetUserIdAsync(target);

                if (targetId == ObjectId.Empty)
                    throw new KeyNotFoundException("User not found");

                await _users.UpdateOneAsync(u => u._id == senderId,
                    Builders<UserModel>.Update.AddToSet(u => u.OutgoingFriendRequests, targetId));

                await _users.UpdateOneAsync(u => u._id == targetId,
                    Builders<UserModel>.Update.AddToSet(u => u.IncomingFriendRequests, senderId));
                string userId = senderId.ToString();
                
                
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task RemoveFriendRequest(string sender, string target)
        {
            try
            {
                var senderId = await GetUserIdAsync(sender);
                var targetId = await GetUserIdAsync(target);

                if (targetId == ObjectId.Empty)
                    throw new KeyNotFoundException("User not found");

                await RemoveFriendRequest(senderId, targetId);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private async Task RemoveFriendRequest(ObjectId senderId, ObjectId targetId)
        {
            try
            {
                await _users.UpdateOneAsync(u => u._id == senderId,
                    Builders<UserModel>.Update.Pull(u => u.OutgoingFriendRequests, targetId));
                
                await _users.UpdateOneAsync(u => u._id == targetId,
                    Builders<UserModel>.Update.Pull(u => u.IncomingFriendRequests, senderId));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task AddFriend(string sender, string target)
        {
            try
            {
                var senderId = await GetUserIdAsync(sender);
                var targetId = await GetUserIdAsync(target);

                if (targetId == ObjectId.Empty)
                    throw new KeyNotFoundException("User not found");

                await RemoveFriendRequest(targetId, senderId);
                
                await _users.UpdateOneAsync(u => u._id == senderId,
                    Builders<UserModel>.Update.AddToSet(u => u.Friends, targetId));

                await _users.UpdateOneAsync(u => u._id == targetId,
                    Builders<UserModel>.Update.AddToSet(u => u.Friends, senderId));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task RemoveFriend(string sender, string target)
        {
            try
            {
                var senderId = await GetUserIdAsync(sender);
                var targetId = await GetUserIdAsync(target);

                if (targetId == ObjectId.Empty)
                    throw new KeyNotFoundException("User not found");
                
                await _users.UpdateOneAsync(u => u._id == senderId,
                    Builders<UserModel>.Update.Pull(u => u.Friends, targetId));
                
                await _users.UpdateOneAsync(u => u._id == targetId,
                    Builders<UserModel>.Update.Pull(u => u.Friends, senderId));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private async Task<ObjectId> GetUserIdAsync(string username)
        {
            return await _users.Find(u => u.Username == username).Project(u => u._id).FirstOrDefaultAsync();
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
                    Builders<UserModel>.Update.Set(user => user.IsEmailConfirmed, true));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        

        public async Task UpdateUserPasswordAsync(UserModel user, string p)
        {
            var filter = Builders<UserModel>.Filter.Eq(u => u.Email, user.Email);
            var update = Builders<UserModel>.Update.Set(u => u.Password, p);
            var result = await _users.UpdateOneAsync(filter, update);
        }
        
        /// <summary>
        /// Реєструє нового користувача в системі.
        /// </summary>
        /// <param name="user">Об'єкт користувача для реєстрації.</param>
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

        /// <summary>
        /// Отримує об'єкт користувача за його електронною поштою асинхронно.
        /// </summary>
        /// <param name="email">Електронна пошта користувача.</param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public Task<UserModel> GetUserByEmailAsync(string email)
        {
                return _users.Find(u => u.Email == email)?.FirstOrDefaultAsync();
        }

        /// <summary>
        /// Отримує об'єкт користувача за його іменем користувача асинхронно.
        /// </summary>
        /// <param name="username">Ім'я користувача. </param>
        /// <returns>Об'єкт користувача або <c>null</c>, якщо користувача не знайдено.</returns>
        public async Task<UserModel> GetUserByUsernameAsync(string username)
        {
            return await _users.Find(u => u.Username == username)?.FirstOrDefaultAsync();
        }

        public async Task<IEnumerable<UserModel>> GetAllUsersAsync()
        {
            return await _users.Find(_ => true).ToListAsync();
        }

    }
}