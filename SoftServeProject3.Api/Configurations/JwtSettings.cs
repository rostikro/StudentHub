namespace SoftServeProject3.Api.Configurations
{
    //configure jwt token settings(secret is generated in KeyGenerator.cs)
    public class JwtSettings
    {
        public int ExpirationInMinutes { get; set; }

    }   
}
