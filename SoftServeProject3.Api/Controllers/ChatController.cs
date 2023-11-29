using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Services;
using SoftServeProject3.Core.DTOs;
using System.Threading.Tasks;

namespace SoftServeProject3.Api.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ChatController : ControllerBase
    {
        private readonly IMessageRepository _messageRepository;
        private readonly IJwtService _jwtService;

        public ChatController(IMessageRepository messageRepository, IJwtService jwtService)
        {
            _messageRepository = messageRepository;
            _jwtService = jwtService;
        }

        [HttpGet("history")]
        [Authorize]
        public async Task<IActionResult> GetChatHistory(string user2)
        {
            var authUser = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Username;
            var messages = await _messageRepository.GetMessagesAsync(authUser, user2);
            return Ok(messages);
        }

        [HttpGet("recent-contacts")]
        [Authorize]
        public async Task<IActionResult> GetRecentContactsAsync()
        {
            var currentUsername = _jwtService.DecodeJwtToken(HttpContext.Request.Headers["Authorization"].ToString().Split(" ").Last()).Username;
            var recentContacts = await _messageRepository.GetRecentContactsAsync(currentUsername);

            if (recentContacts == null || !recentContacts.Any())
            {
                return NotFound("No recent contacts found.");
            }

            return Ok(recentContacts);
        }
    }
}
