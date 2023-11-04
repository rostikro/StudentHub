using System.Security.Claims;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Configurations
{
    public interface IJwtService
    {
        string GenerateJwtToken(List<Claim> claims);
        UserInfo DecodeJwtToken(string token);
    }
}
