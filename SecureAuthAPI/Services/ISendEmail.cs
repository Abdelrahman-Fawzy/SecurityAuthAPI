namespace SecureAuthAPI.Services
{
    public interface ISendEmail
    {
        Task SendEmailMessage(string toEmail, string subject, string body);
    }
}
