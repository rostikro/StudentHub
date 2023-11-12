using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        
        Task UpdateUserAsync(string email);
        Task UpdateProfileAsync(UpdateProfile profile, string email);
        Task<bool> IsUserExistsAsync(string email);
        void Register(UserModel user);
        Task<UserModel> GetUserByEmailAsync(string email);
        Task<UserModel> GetUserByUsernameAsync(string username);
        Task<IEnumerable<UserModel>> GetAllUsersAsync();
        Task UpdateUserPasswordAsync(UserModel user, string password);

    }
}