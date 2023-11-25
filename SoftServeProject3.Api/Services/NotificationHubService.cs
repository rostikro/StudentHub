using Microsoft.AspNetCore.SignalR;

namespace SoftServeProject3.Api.Services
{
    public class NotificationHubService : Hub
    {
        public async Task SendFriendRequestUpdate(string userId)
        {
            await Clients.User(userId).SendAsync("ReceiveFriendRequestUpdate");
        }
    }
}
