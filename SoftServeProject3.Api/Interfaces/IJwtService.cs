using System.Security.Claims;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Interfaces
{
    public interface IJwtService
    {
        string GenerateJwtToken(List<Claim> claims);
        UserInfo DecodeJwtToken(string token);
    }
}
