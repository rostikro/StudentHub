using Microsoft.AspNetCore.SignalR;

public class ChatHub : Hub
{
    public override async Task OnConnectedAsync()
    {
        var username = Context.User?.Identity?.Name;
        Console.WriteLine($"User connected: {username}");
        await base.OnConnectedAsync();
    }

    public async Task SendMessageToUser(string receiverUserId, string message)
    {
        Console.WriteLine($"Sending message from {Context.UserIdentifier} to {receiverUserId}");
        await Clients.User(receiverUserId).SendAsync("ReceiveMessage", Context.UserIdentifier, message);
    }
}