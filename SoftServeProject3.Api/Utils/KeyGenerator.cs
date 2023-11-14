using System;
using System.Security.Cryptography;
using System.Text;

public class KeyGenerator
{
    public static string GenerateRandomKey()
    {
        var randomNumber = new byte[32];
        string refreshToken = "";

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            refreshToken = Convert.ToBase64String(randomNumber);
            return refreshToken;
        }
    }
}