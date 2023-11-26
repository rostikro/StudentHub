﻿using Microsoft.AspNetCore.SignalR;
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
            Timestamp = DateTime.UtcNow
        };

        await _messageRepository.SaveMessageAsync(newMessage);
        await Clients.User(receiverUserId).SendAsync("ReceiveMessage", senderUsername, message, currentTime);
    }
}