using SoftServeProject3.Api.Entities;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IUserRepository
    {
        User GetByEmail(string email);
        void Register(User user);

    }
}
