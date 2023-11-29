using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SoftServeProject3.Api.Services
{
    public class CustomUserIdProvider : IUserIdProvider
    {
        public string GetUserId(HubConnectionContext connection)
        {
            Console.WriteLine("sTART");
            return connection.User?.Identity?.Name;
        }
    }
}
