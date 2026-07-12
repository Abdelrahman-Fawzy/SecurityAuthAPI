
using MailKit.Net.Smtp;
using MimeKit;

namespace SecureAuthAPI.Services
{
    public class SendEmail : ISendEmail
    {
        private readonly IConfiguration _configuration;

        public SendEmail(IConfiguration configuration) => _configuration = configuration;

        public async Task SendEmailMessage(string toEmail, string subject, string body)
        {
            var emailMessage = new MimeMessage();

            emailMessage.From.Add(new MailboxAddress("نظام الامان", _configuration["EmailSettings:From"]));

            emailMessage.To.Add(new MailboxAddress("", toEmail));

            emailMessage.Subject = subject;

            var bodyBuilder = new BodyBuilder { HtmlBody = body };
            emailMessage.Body = bodyBuilder.ToMessageBody();

            using var client = new SmtpClient();
            try
            {
                await client.ConnectAsync(
                    _configuration["EmailSettings:SmtpServer"],
                    int.Parse(_configuration["EmailSettings:Port"]),
                    MailKit.Security.SecureSocketOptions.StartTls
                );

                await client.AuthenticateAsync(_configuration["EmailSettings:Username"], _configuration["EmailSettings:Password"]);

                await client.SendAsync(emailMessage);
            }
            finally
            {
                await client.DisconnectAsync(true);
            }
        }
    }
}
