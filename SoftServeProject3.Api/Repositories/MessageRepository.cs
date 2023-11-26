using MongoDB.Driver;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Repositories
{
    public class MessageRepository : IMessageRepository
    {
        private readonly IMongoCollection<Message> _messages;

        public MessageRepository(string connectionString)
        {
            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");
            _messages = database.GetCollection<Message>("messages");
        }

        public async Task SaveMessageAsync(Message message)
        {
            await _messages.InsertOneAsync(message);
        }

        public async Task<List<Message>> GetMessagesAsync(string user1, string user2)
        {
            var filter = Builders<Message>.Filter.Or(
                Builders<Message>.Filter.And(
                    Builders<Message>.Filter.Eq(m => m.SenderUsername, user1),
                    Builders<Message>.Filter.Eq(m => m.ReceiverUsername, user2)),
                Builders<Message>.Filter.And(
                    Builders<Message>.Filter.Eq(m => m.SenderUsername, user2),
                    Builders<Message>.Filter.Eq(m => m.ReceiverUsername, user1))
            );

            return await _messages.Find(filter).SortBy(m => m.Timestamp).ToListAsync();
        }
    }

}
