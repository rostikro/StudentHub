using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Repositories;
using System.Text;
using SoftServeProject3.Api.Configurations;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace SoftServeProject3.Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(
                    builder =>
                    {
                        builder.AllowAnyOrigin()
                               .AllowAnyMethod()
                               .AllowAnyHeader();
                    });
            });
            var mongoDBConnectionString = builder.Configuration["MongoDBSettings:ConnectionString"] ?? throw new InvalidOperationException("MongoDB connection string is not set in the configuration.");
            
            builder.Services.AddSingleton<IUserRepository>(sp => new UserRepository(mongoDBConnectionString));
            builder.Services.AddControllers();
            var jwtSettings = new JwtSettings();
            builder.Configuration.GetSection(nameof(JwtSettings)).Bind(jwtSettings);
            builder.Services.AddSingleton(jwtSettings);

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; 
                options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme; 
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; 
            })
            .AddCookie(options =>
            {
                options.LoginPath = "/signin-google";
            })
            .AddJwtBearer(x =>
            {
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings.Secret)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    ValidateLifetime = true
                };
            })
            .AddGoogle(googleOptions =>
            {
                googleOptions.ClientId = builder.Configuration["GoogleOAuth:ClientId"];
                googleOptions.ClientSecret = builder.Configuration["GoogleOAuth:ClientSecret"];
                googleOptions.CallbackPath = "/signin-google"; // /signin-google
            }); ;


            var configuration = builder.Configuration;

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseCors();
            app.UseAuthentication();  
            app.UseAuthorization();
            app.MapControllers();
            app.Run();
        }
    }
}
