using System.Security.Claims;

namespace SoftServeProject3.Api.Configurations
{
    public interface IJwtService
    {
        string GenerateJwtToken(List<Claim> claims);
    }
}
