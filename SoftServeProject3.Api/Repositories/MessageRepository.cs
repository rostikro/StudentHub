using MongoDB.Driver;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;
using System;

namespace SoftServeProject3.Api.Repositories
{
    public class MessageRepository : IMessageRepository
    {
        private readonly IMongoCollection<UserPair> _userPairs;
        private readonly IMongoCollection<Chat> _chats;

        public MessageRepository(string connectionString)
        {
            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");
            _userPairs = database.GetCollection<UserPair>("userPairs");
            _chats = database.GetCollection<Chat>("chats");
        }

        public async Task SaveMessageAsync(Message message, string user1, string user2)
        {
            var userPairFilter = Builders<UserPair>.Filter.And(
    Builders<UserPair>.Filter.All(pair => pair.Users, new List<string> { user1 }),
    Builders<UserPair>.Filter.All(pair => pair.Users, new List<string> { user2 }),
    Builders<UserPair>.Filter.Size(pair => pair.Users, 2)
);

            var userPair = await _userPairs.Find(userPairFilter).FirstOrDefaultAsync();

            if (userPair == null)
            {
                userPair = new UserPair
                {
                    Users = new List<string> { user1, user2 },
                    LastMessageTimestamp = DateTime.UtcNow
                };

                var newChat = new Chat { Messages = new List<Message> { message } };
                await _chats.InsertOneAsync(newChat);
                userPair.ChatId = newChat.Id;

                await _userPairs.InsertOneAsync(userPair); 
            }
            else
            {
                if (userPair.ChatId != null)
                {
                    await _chats.UpdateOneAsync(
                        Builders<Chat>.Filter.Eq(chat => chat.Id, userPair.ChatId),
                        Builders<Chat>.Update.AddToSet(chat => chat.Messages, message)
                    );
                }

                await _userPairs.UpdateOneAsync(
                    Builders<UserPair>.Filter.Eq(pair => pair.Id, userPair.Id),
                    Builders<UserPair>.Update.Set(pair => pair.LastMessageTimestamp, DateTime.UtcNow)
                );
            }
        }

        public async Task<List<Message>> GetMessagesAsync(string user1, string user2)
        {
            var userPair = await _userPairs.Find(pair => pair.Users.Contains(user1) && pair.Users.Contains(user2)).FirstOrDefaultAsync();
            if (userPair?.ChatId != null)
            {
                var chat = await _chats.Find(chat => chat.Id == userPair.ChatId).FirstOrDefaultAsync();
                return chat?.Messages ?? new List<Message>();
            }
            return new List<Message>();
        }

        public async Task<List<string>> GetRecentContactsAsync(string username)
        {
            var recentChats = await _userPairs.Find(pair => pair.Users.Contains(username))
                                              .SortByDescending(pair => pair.LastMessageTimestamp)
                                              .Limit(10)  
                                              .ToListAsync();

            var recentContacts = new List<string>();
            foreach (var pair in recentChats)
            {
                var otherUser = pair.Users.FirstOrDefault(u => u != username);
                if (!string.IsNullOrEmpty(otherUser))
                {
                    recentContacts.Add(otherUser);
                }
            }

            return recentContacts;
        }

    }

}
