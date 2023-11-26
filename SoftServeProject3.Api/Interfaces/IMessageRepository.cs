using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IMessageRepository
    {
        Task SaveMessageAsync(Message message);
        Task<List<Message>> GetMessagesAsync(string user1, string user2);
    }
}
