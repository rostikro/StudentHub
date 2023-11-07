using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using SoftServeProject3.UI;
using System.Net.Http;
using Microsoft.Extensions.DependencyInjection;  
using Microsoft.JSInterop;
using SoftServeProject3.UI.Services;

namespace SoftServeProject3.UI
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebAssemblyHostBuilder.CreateDefault(args);
            builder.RootComponents.Add<App>("#app");
            builder.RootComponents.Add<HeadOutlet>("head::after");

            // Реєстрація HttpClient для використання по всьому додатку
            builder.Services.AddTransient(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });

            // Реєстрація TokenService
            builder.Services.AddScoped<TokenService>();

            // Реєстрація UserProfileService
            builder.Services.AddScoped<UserProfileService>();

            var host = builder.Build();

            // Ініціалізація HttpClient з токеном аутентифікації
            var tokenService = host.Services.GetRequiredService<TokenService>();
            var httpClient = host.Services.GetRequiredService<HttpClient>();
            var token = await tokenService.GetToken();
            if (!string.IsNullOrEmpty(token))
            {
                Console.WriteLine("Attempting to set token: " + token);
                httpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            }
            else
            {
                Console.WriteLine("Unable to find Token");
            }

            // Запуск додатку
            await host.RunAsync();
        }
    }

    
}