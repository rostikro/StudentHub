using MongoDB.Driver;
using SoftServeProject3.Api.Entities;
using SoftServeProject3.Api.Interfaces;
using SoftServeProject3.Core.DTOs;
using System.Diagnostics;
using System.Security.Cryptography;

namespace SoftServeProject3.Api.Repositories
{
    public class VerificationRepository : IVerificationRepository
    {
        private readonly IMongoCollection<ForgotPasswordModel> _verifications;
        public const int CAN_RESEND_CODE_IN_MIN = 1;
        public const int EXPIRE_IN_MINUTES = 10;

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
                                    Builders<ForgotPasswordModel>.Update.Set(verification =>
                                    verification.Code, resetData.Code));
                Debug.WriteLine(resetData.Code);
                
                //add 1 minute to wait
                await _verifications.UpdateOneAsync(verification => verification.Email == resetData.Email,
                    Builders<ForgotPasswordModel>.Update.Set(verification =>
                    verification.ResendCode, DateTime.UtcNow.AddMinutes(CAN_RESEND_CODE_IN_MIN)));
                //add 10 minutes to expire
                await _verifications.UpdateOneAsync(verification => verification.Email == resetData.Email,
                    Builders<ForgotPasswordModel>.Update.Set(verification =>
                    verification.ExpirationTime, DateTime.UtcNow.AddMinutes(EXPIRE_IN_MINUTES)));
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

        public async Task<ForgotPasswordModel> GetByHashCode(string hashCode)
        {
            try
            {
                var verification = _verifications.Find(user => user.Code == hashCode).FirstOrDefault();

                var filter = Builders<ForgotPasswordModel>.Filter.Empty;
                await _verifications.Find(filter).ForEachAsync(ver =>
                {
                    if (BCrypt.Net.BCrypt.Verify(ver.Code, hashCode))
                    {
                        verification = ver;
                    }
                });

                if (verification == null)
                {
                    Console.WriteLine($"No verification found with code: {hashCode}");
                }
                else
                {
                    Console.WriteLine($"Verification found with code: {hashCode}");
                }
                return verification;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error fetching user by code: {ex.Message}");
                return null;
            }
        }
        public void CreateVerification(ForgotPasswordModel verification)
        {
            try
            {
                Debug.WriteLine(verification.Code);
                verification.Code = BCrypt.Net.BCrypt.HashPassword(verification.Code);
                verification.ResendCode = DateTime.UtcNow.AddMinutes(CAN_RESEND_CODE_IN_MIN);
                verification.ExpirationTime = DateTime.UtcNow.AddMinutes(EXPIRE_IN_MINUTES);
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

        //clear the verifications which has been expired
        public async Task ClearVerifications()
        {
            var filter = Builders<ForgotPasswordModel>.Filter.Empty;
            await _verifications.Find(filter).ForEachAsync(item =>
            {
                if (item.ExpirationTime < DateTime.UtcNow)
                    _verifications.DeleteOneAsync(ver => ver == item);
            });
        }
    }
}


