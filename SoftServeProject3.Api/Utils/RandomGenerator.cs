namespace SoftServeProject3.Api.Utils;

public static class RandomGenerator
{
     
    
    public static string GenerateRandomCode()
    {
        var chars = "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"; // 62 chars

        Random rnd = new Random();

        string result = "";
        for (int i = 0; i < 6; i++)
        {
            result += chars[rnd.Next(chars.Length)];
        }

        return result;
    }
}