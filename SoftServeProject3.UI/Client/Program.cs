using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SoftServeProject3.UI;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;  
using Microsoft.JSInterop;

namespace SoftServeProject3.UI
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("#app");
            builder.RootComponents.Add<HeadOutlet>("head::after");
            builder.Services.AddTransient(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
            
            builder.Services.AddScoped<TokenService>();

            
            builder.Services.AddScoped(async sp =>
            {
                var httpClient = new HttpClient { BaseAddress = new Uri("https://localhost:7292") };
                var tokenService = sp.GetRequiredService<TokenService>();
                var token = await tokenService.GetToken();

                if (!string.IsNullOrEmpty(token))
                {
                    Console.WriteLine("Attempting to save token: " + token);
                    httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                }
                else
                {
                    Console.WriteLine("Unable to find Token");
                }

                return httpClient;
            });

            await builder.Build().RunAsync();
        }
    }

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