using Microsoft.AspNetCore.SignalR;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;

public class ChatHub : Hub
{
    private readonly IMessageRepository _messageRepository;

    public ChatHub(IMessageRepository messageRepository)
    {
        _messageRepository = messageRepository;
    }

    public override async Task OnConnectedAsync()
    {
        var username = Context.User?.Identity?.Name;
        Console.WriteLine($"User connected: {username}");
        await base.OnConnectedAsync();
    }

    public async Task SendMessageToUser(string receiverUserId, string message)
    {
        var senderUsername = Context.UserIdentifier;
        var currentTime = DateTime.Now.ToString("dd/MM/yyyy HH:mm");
        var newMessage = new Message
        {
            SenderUsername = senderUsername,
            ReceiverUsername = receiverUserId,
            Text = message,
            Timestamp = DateTime.Now
        };

        await _messageRepository.SaveMessageAsync(newMessage, senderUsername, receiverUserId);
        await Clients.User(receiverUserId).SendAsync("ReceiveMessage", senderUsername, message, currentTime);
    }

    public async Task UserTyping(string receiverUserId)
    {
        var senderUsername = Context.UserIdentifier;
        await Clients.User(receiverUserId).SendAsync("UserTyping", senderUsername);
    }

    //індикатор прочитаного повідомлення, мб додам пізніше
    public async Task MessageRead(string receiverUserId, string messageId)
    {
        var senderUsername = Context.UserIdentifier;
        await Clients.User(receiverUserId).SendAsync("MessageRead", senderUsername, messageId);
    }

    public async Task UpdateOutgoingList(string receiverUserId)
    {
        var senderUsername = Context.UserIdentifier;
        await Clients.User(receiverUserId).SendAsync("UpdateOutgoingList", senderUsername);
    }

    public async Task UpdateSearchList()
    {
        await Clients.All.SendAsync("UpdateSearchList");
    }

    public async Task UpdateOtherProfile()
    {
        await Clients.All.SendAsync("UpdateOtherProfile");
    }
}