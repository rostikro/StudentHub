using System;
using System.Security.Cryptography;
using System.Text;

public class KeyGenerator
{
    public static string GenerateRandomKey(int length)
    {
        using (var cryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] data = new byte[length];
            cryptoProvider.GetBytes(data);
            return Convert.ToBase64String(data);
        }
    }
}