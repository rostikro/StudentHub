using Microsoft.JSInterop;

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
