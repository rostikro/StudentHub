using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IMessageRepository
    {
        Task SaveMessageAsync(Message message, string user1, string user2);
        Task<List<Message>> GetMessagesAsync(string user1, string user2);
        Task<List<string>> GetRecentContactsAsync(string username);
    }
}
