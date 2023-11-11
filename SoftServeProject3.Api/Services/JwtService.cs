using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using SoftServeProject3.Api.Configurations;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;


public class JwtService : IJwtService
{
    private readonly string _jwtSecret; // Your JWT secret
    private readonly JwtSettings _jwtSettings; // Your JWT settings

    public JwtService(string sekretKey, JwtSettings jwtSettings)
    {
        _jwtSecret = sekretKey;
        _jwtSettings = jwtSettings;

    }

    // Method to generate a JWT token
    public string GenerateJwtToken(List<Claim> claims)
    {

        // Create a new instance of the JWT security token handler
        var tokenHandler = new JwtSecurityTokenHandler();

        // Convert the JWT secret to bytes for security
        var key = Encoding.ASCII.GetBytes(_jwtSecret);

        // Define the token descriptor with claims, expiration, and signing credentials
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),  // Claims associated with the user
            Expires = DateTime.Now.AddMinutes(_jwtSettings.ExpirationInMinutes),  // Token expiration time
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),  // Security key for signing the token
                SecurityAlgorithms.HmacSha256Signature  // Signing algorithm
            )
        };

        // Create the JWT token based on the descriptor
        var token = tokenHandler.CreateToken(tokenDescriptor);

        // Write the token as a string
        return tokenHandler.WriteToken(token);

        // The generated token is returned as a string, and it's typically sent as part of a response to a client after successful authentication.
    }

    /// <summary>
    /// Декодує JWT токен і витягує інформацію користувача.
    /// </summary>
    /// <param name="token">JWT токен, який необхідно декодувати.</param>
    /// <returns>Об'єкт <see cref="UserInfo"/>, що містить інформацію про користувача.</returns>
    public UserInfo DecodeJwtToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSecret);
        tokenHandler.ValidateToken(token, new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        }, out SecurityToken validatedToken);

        var jwtToken = (JwtSecurityToken)validatedToken;
        var userEmail = jwtToken.Claims.First(x => x.Type == "email").Value;
        var userUsername = jwtToken.Claims.First(x => x.Type == "unique_name").Value;

        return new UserInfo { Email = userEmail, Username = userUsername };
    }
}
