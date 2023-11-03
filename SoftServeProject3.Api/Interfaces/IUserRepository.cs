using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        Task UpdateUserAsync(User user);
        Task UpdateUserAsync(string email);
        Task UpdateProfileAsync(UpdateProfile profile);
        Task<bool> IsUserExistsAsync(string email);
        User GetByEmail(string email);
        User GetByUsername(string username);
        void Register(User user);
        Task<User> GetUserByEmailAsync(string email);
        Task<User> GetUserByUsernameAsync(string username);
        Task<IEnumerable<User>> GetAllUsersAsync();

    }
}
