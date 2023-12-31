﻿using SoftServeProject3.Api.Entities;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IVerificationRepository
    {
        Task UpdateCodeAsync(ForgotPasswordModel resetData);
        Task<bool> IsUserExistsAsync(string email);
        Task<ForgotPasswordModel> GetByEmail(string email);
        Task<ForgotPasswordModel> GetByHashCode(string hashCode);
        Task CreateVerification(ForgotPasswordModel verification);
        bool RemoveVerification(string email);
        Task ClearVerifications();
    }
}
