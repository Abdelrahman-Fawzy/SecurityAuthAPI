using Microsoft.AspNetCore.Identity;

namespace SecureAuthAPI.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FullName { get; set; } = String.Empty;
    }
}
