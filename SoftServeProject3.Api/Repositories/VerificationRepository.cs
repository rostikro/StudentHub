using MongoDB.Driver;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;

namespace SoftServeProject3.Api.Repositories
{
    public class VerificationRepository : IVerificationRepository
    {
        private readonly IMongoCollection<ForgotPasswordModel> _verifications;
        public const int CAN_RESEND_CODE_IN_MIN = 1;

        public VerificationRepository(string connectionString)
        {

            var client = new MongoClient(connectionString);
            var database = client.GetDatabase("test");

            _verifications = database.GetCollection<ForgotPasswordModel>("verify user");
        }

        public async Task<bool> IsUserExistsAsync(string email)
        {
            try
            {
                var user = await _verifications.Find(user => user.Email == email).FirstOrDefaultAsync();

                return user != null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public async Task UpdateCodeAsync(ForgotPasswordModel resetData)
        {
            try
            {
                await _verifications.UpdateOneAsync(verification => verification.Email == resetData.Email,
                    Builders<ForgotPasswordModel>.Update.Set(verification => verification.Code, resetData.Code));

                await _verifications.UpdateOneAsync(verification => verification.Email == resetData.Email,
                    Builders<ForgotPasswordModel>.Update.Set(verification => verification.ResendCode, DateTime.UtcNow.AddMinutes(CAN_RESEND_CODE_IN_MIN)));
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public ForgotPasswordModel GetByEmail(string email)
        {
            try
            {


                var verification = _verifications.Find(user => user.Email == email).FirstOrDefault();

                if (verification == null)
                {
                    Console.WriteLine($"No verification found with email: {email}");

                }
                else
                {
                    Console.WriteLine($"Verification found with email: {email}");
                }

                return verification;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user by email: {ex.Message}");
                return null;
            }
        }
        public void CreateVerification(ForgotPasswordModel verification)
        {
            try
            {

                verification.Code = BCrypt.Net.BCrypt.HashPassword(verification.Code);
                verification.ResendCode = DateTime.UtcNow.AddMinutes(CAN_RESEND_CODE_IN_MIN);
                _verifications.InsertOne(verification);
                Console.WriteLine($"Verification created with email: {verification.Email}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error registering user: {ex.Message}");
                throw;
            }
        }

        public bool RemoveVerification(string email)
        {
            try
            {

                var result = _verifications.DeleteOne(ver => ver.Email == email);

                return result != null;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

    }
}


