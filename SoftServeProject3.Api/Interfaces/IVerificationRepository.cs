using SoftServeProject3.Api.Entities;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IVerificationRepository
    {
        Task UpdateCodeAsync(ForgotPasswordModel resetData);
        Task<bool> IsUserExistsAsync(string email);
        ForgotPasswordModel GetByEmail(string email);
        Task<ForgotPasswordModel> GetByHashCode(string hashCode);
        void CreateVerification(ForgotPasswordModel verification);
        bool RemoveVerification(string email);
        Task ClearVerifications();
    }
}
