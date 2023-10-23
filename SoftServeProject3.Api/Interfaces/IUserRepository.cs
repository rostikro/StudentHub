using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        Task UpdateUserAsync(string email);
        Task<bool> IsUserExistsAsync(string email);
        User GetByEmail(string email);
        User GetByUsername(string username);
        void Register(User user);

    }
}
