using Microsoft.JSInterop;
using SoftServeProject3.Core.DTOs;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using SoftServeProject3.UI.Services;

namespace SoftServeProject3.UI.Services
{
    public class UserProfileService
    {
        private readonly HttpClient _httpClient;
        private readonly TokenService _tokenService;

        public UserProfileService(HttpClient httpClient, TokenService tokenService)
        {
            _httpClient = httpClient;
            _tokenService = tokenService;
        }

        public async Task<UpdateProfile> GetProfileAsync()
        {
            var token = await _tokenService.GetToken();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.GetAsync("https://localhost:7292/Users/profile"); 
            response.EnsureSuccessStatusCode();

            var user = await response.Content.ReadFromJsonAsync<UpdateProfile>();
            return user;
        }


        public async Task<bool> UpdateProfileAsync(UpdateProfile user)
        {
            var token = await _tokenService.GetToken();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.PostAsJsonAsync("https://localhost:7292/Users/updateProfile", user);
            return response.IsSuccessStatusCode;
        }
    }
}
