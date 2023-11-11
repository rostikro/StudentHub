using System.Text;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson.Serialization.Serializers;
using MongoDB.Bson.Serialization;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Api.Repositories;
using SoftServeProject3.Api.Services;
using SoftServeProject3.Api.Configurations;


namespace SoftServeProject3.Api
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            ConfigureServices(builder);

            var app = builder.Build();

            ConfigureHttpPipeline(app);

            app.Run();
        }

        private static void ConfigureServices(WebApplicationBuilder builder)
        {
            // CORS
            ConfigureCors(builder);

            // Конфігурація пошти
            ConfigureEmailService(builder);

            // MongoDB
            ConfigureMongoDB(builder);

            //Токін і автентифікація
            ConfigureAuthentication(builder);

            // Свагер
            ConfigureSwagger(builder);
        }

        #region Service Configuration Methods

        private static void ConfigureCors(WebApplicationBuilder builder)
        {
            builder.Services.AddCors(options =>
            {
                options.AddDefaultPolicy(policyBuilder =>
                {
                    policyBuilder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
                });
            });
        }

        private static void ConfigureEmailService(WebApplicationBuilder builder)
        {
            builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
            builder.Services.AddTransient<IEmailService, EmailService>();

            builder.Services.AddHttpClient("EmailClient", (services, client) =>
            {
                var emailSettings = services.GetRequiredService<IOptions<EmailSettings>>().Value;
                client.BaseAddress = new Uri(emailSettings.ApiBaseUrl);
                client.DefaultRequestHeaders.Add("Api-Token", emailSettings.ApiToken);
            });
        }

        private static void ConfigureMongoDB(WebApplicationBuilder builder)
        {
            var mongoDBConnectionString = builder.Configuration["MongoDBSettings:ConnectionString"]
                ?? throw new InvalidOperationException("MongoDB connection string is not set in the configuration.");

            builder.Services.AddSingleton<IUserRepository>(sp => new UserRepository(mongoDBConnectionString));
            builder.Services.AddSingleton<IVerificationRepository>(sp => new VerificationRepository(mongoDBConnectionString));
            builder.Services.AddControllers();

            BsonSerializer.RegisterSerializer(typeof(DateTime), new DateTimeSerializer(DateTimeKind.Local));
        }

        private static void ConfigureAuthentication(WebApplicationBuilder builder)
        {
            var jwtSettings = new JwtSettings();
            builder.Configuration.GetSection(nameof(JwtSettings)).Bind(jwtSettings);
            builder.Services.AddSingleton(jwtSettings);

            var secretKey = builder.Configuration["JwtSettings:SecretKey"];
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("JWT Secret key is not set in the configuration.");
            }

            builder.Services.AddTransient<IJwtService>(sp => new JwtService(secretKey, jwtSettings));

            ConfigureAuthServices(builder, secretKey);
        }

        private static void ConfigureAuthServices(WebApplicationBuilder builder, string secretKey)
        {
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddCookie(options => { options.LoginPath = "/signin-google"; })
            .AddJwtBearer(x =>
            {
                x.SaveToken = true;
                x.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    RequireExpirationTime = false,
                    ValidateLifetime = true
                };
            })
            .AddGoogle(googleOptions =>
            {
                var googleClientId = builder.Configuration["GoogleOAuth:ClientId"];
                if (string.IsNullOrEmpty(googleClientId))
                {
                    throw new InvalidOperationException("Google OAuth ClientId is not set in the configuration.");
                }
                googleOptions.ClientId = googleClientId;

                var googleClientSecret = builder.Configuration["GoogleOAuth:ClientSecret"];
                if (string.IsNullOrEmpty(googleClientSecret))
                {
                    throw new InvalidOperationException("Google OAuth ClientSecret is not set in the configuration.");
                }
                googleOptions.ClientSecret = googleClientSecret;

                googleOptions.CallbackPath = "/signin-google";
            });
        }

        private static void ConfigureSwagger(WebApplicationBuilder builder)
        {
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
        }

        #endregion

        private static void ConfigureHttpPipeline(WebApplication app)
        {
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
        }
    }
}
