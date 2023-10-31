using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        Task UpdateUserAsync(string email);
        Task<bool> IsUserExistsAsync(string email);
        UserModel GetByEmail(string email);
        UserModel GetByUsername(string username);
        void Register(UserModel user);

    }
}