using Microsoft.JSInterop;
using System.IdentityModel.Tokens.Jwt;

namespace SoftServeProject3.UI.Services
{
    public class TokenService
    {
        private readonly IJSRuntime _jsRuntime;
        private readonly string tokenKey = "userToken";

        public TokenService(IJSRuntime jsRuntime)
        {
            _jsRuntime = jsRuntime;
        }

        public bool IsTokenValid(string token)
        {
            try
            {
                var handler = new JwtSecurityTokenHandler();
                var jsonToken = handler.ReadToken(token) as JwtSecurityToken;
                var expClaim = jsonToken?.Claims.FirstOrDefault(claim => claim.Type == "exp")?.Value;

                if (expClaim != null)
                {
                    var expTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim));
                    return expTime > DateTimeOffset.UtcNow;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }

        public async Task StoreToken(string token)
        {
            await _jsRuntime.InvokeVoidAsync("localStorageFunctions.setItem", tokenKey, token);
        }

        public async Task<string> GetToken()
        {
            return await _jsRuntime.InvokeAsync<string>("localStorageFunctions.getItem", tokenKey);
        }

        public async Task RemoveToken()
        {
            await _jsRuntime.InvokeVoidAsync("localStorageFunctions.removeItem", tokenKey);
        }
    }
}
