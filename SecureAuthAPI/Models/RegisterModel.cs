namespace SecureAuthAPI.Models
{
    public class RegisterModel
    {
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;

        public List<string> Roles { get; set; } = new List<string> { "User" };
    }
}
