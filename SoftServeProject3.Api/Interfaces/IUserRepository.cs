﻿using MongoDB.Bson;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        
        Task UpdateUserAsync(string email);
        Task UpdateProfileAsync(UpdateProfile profile, string email);
        Task UpdateRecentlyViewedAsync(string senderEmail, ObjectId viewedProfile);
        Task<List<Friend>> GetRecentlyViewedAsync(string email);
        Task<List<Friend>> GetFriendsAsync(string email);
        Task<List<Friend>> GetIncomingFriendRequestsAsync(string email);
        Task<List<Friend>> GetOutgoingFriendRequestsAsync(string email);
        Task AddFriendRequest(string sender, string target);
        Task RemoveFriendRequest(string sender, string target);
        Task AddFriend(string sender, string target);
        Task RemoveFriend(string sender, string target);
        Task<bool> IsUserExistsAsync(string email);
        void Register(UserModel user);
        Task<UserModel> GetUserByEmailAsync(string email);
        Task<UserModel> GetUserByUsernameAsync(string username);
        Task<IEnumerable<UserModel>> GetAllUsersAsync();
        Task UpdateUserPasswordAsync(UserModel user, string password);

    }
}