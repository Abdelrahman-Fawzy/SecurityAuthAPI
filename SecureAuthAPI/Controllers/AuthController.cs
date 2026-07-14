using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SecureAuthAPI.Models;
using SecureAuthAPI.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecureAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _config;
        private readonly ISendEmail _emailMessage;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration config, 
            ISendEmail emailMessage
           )
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _config = config;
            _emailMessage = emailMessage;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if(userExists != null) return BadRequest(new { Message = "هذا الحساب مسجل لدينا بالفعل" });

            var user = new ApplicationUser
            {
                UserName = model.Email,
                Email = model.Email,
                FullName = model.FullName
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded) {

                foreach(var role in model.Roles)
                {
                    if (!await _roleManager.RoleExistsAsync(role))
                        await _roleManager.CreateAsync(new IdentityRole(role));

                    await _userManager.AddToRoleAsync(user, role);
                }

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                var encodedToken = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                var frontendUrl = $"https://localhost:3000/confirm-email?token={encodedToken}&email={user.Email}";

                var mailContent = $@"
                    <h2>تفعيل حسابك الجديد</h2>
                    <p>مرحباً {user.FullName}، شكراً لتسجيلك معنا.</p>
                    <p>يرجى الضغط على الزر أدناه لتفعيل حسابك والتمكن من تسجيل الدخول:</p>
                    <a href='{frontendUrl}' style='padding: 10px 20px; background-color: #28a745; color: white; text-decoration: none; border-radius: 5px; display: inline-block;'>تفعيل الحساب</a>";

                await _emailMessage.SendEmailMessage(user.Email, "تفعيل الحساب", mailContent);

                return Ok(new { Message = "تم تسجيل الحساب بنجاح! يرجى مراجعة بريدك الإلكتروني لتفعيل الحساب." });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            if(string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                return BadRequest(new { Message = "البيانات المرسلة غير صالحة" });
            }

            var user = await _userManager.FindByEmailAsync(email);
            if(user == null) return BadRequest(new { Message = "المستخدم غير موجود" });

            try
            {
                var decodedToken = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(token);
                var normalToken = Encoding.UTF8.GetString(decodedToken);

                var result = await _userManager.ConfirmEmailAsync(user, normalToken);

                if(result.Succeeded) return Ok(new { Message = "تم تفعيل حسابك بنجاح! يمكنك الآن تسجيل الدخول." });

                return BadRequest(new { Message = "فشل تفعيل الحساب، ربما التوكن منتهي أو غير صالح", Errors = result.Errors });
            }
            catch
            {
                return BadRequest(new { Message = "حدث خطأ أثناء معالجة التوكن." });
            }
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if(user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                if(!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return BadRequest(new { Message = "حسابك لم يتم تفعيله بعد! يرجى مراجعة إيميلك وتفعيل الحساب أولاً." });
                }

                var token = await GenerateToken(user);
                var refreshToken = GenerateRefreshToken();

                user.RefreshToken = refreshToken;
                user.DateTimeExpiryTime = DateTime.UtcNow.AddMinutes(2);

                await _userManager.UpdateAsync(user);

                return Ok(new { 
                    Token = token,
                    RefreshToken = refreshToken,
                    Message = "لقد تم تسجيل دخولك بنجاح" });
            }

            return Unauthorized(new { Message = "البريد الإلكتروني أو كلمة المرور غير صحيحة" });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel model)
        {
            if (model == null) return BadRequest(new { Message = "طلب غير صالح" });

            ClaimsPrincipal? principal;

            try
            {
                principal = GetClaimsFromExpiryToken(model.AccessToken);
            }
            catch
            {
                return BadRequest(new { Message = "الـ Access Token المرسل غير صالح بالكامل" });
            }

            if (principal == null) {
                return BadRequest(new { Message = "توكن غير صالح" });
            }

            var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = await _userManager.FindByIdAsync(userId);

            if(user == null || user.RefreshToken != model.RefreshToken || user.DateTimeExpiryTime <= DateTime.UtcNow)
                return BadRequest(new { Message = "الـ Refresh Token غير صالح أو انتهت صلاحيته. يجب تسجيل الدخول مجدداً!" });

            var newAccessToken = await GenerateToken(user);
            var newRefreshToken = GenerateRefreshToken();

            user.RefreshToken = newRefreshToken;
            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                Token = newAccessToken,
                RefreshToken = newRefreshToken
            });

        }

        [HttpPost("ForgetPassword")]
        public async Task<IActionResult> ForgetPassword(ForgetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return Ok(new { Message = "إذا كان الحساب موجود ,فقد تم إرسال الايميل" });

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var encodedToken = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            var frontendUrl = $"https://localhost:3000/reset-password?token={encodedToken}&email={user.Email}";

            var mailContent = $@"
                <h2>طلب إعادة تعيين كلمة المرور</h2>
                <p>مرحباً {user.FullName}، لقد تلقينا طلباً لإعادة تعيين كلمة المرور الخاصة بك.</p>
                <p>يرجى الضغط على الزر أدناه لتغيير الباسورد (هذا الرابط صالح لفترة مؤقتة):</p>
                <a href='{frontendUrl}' style='padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; display: inline-block;'>إعادة تعيين كلمة المرور</a>
                <p>إذا لم تكن أنت من طلب هذا، يمكنك تجاهل هذا الإيميل بأمان.</p>";

            await _emailMessage.SendEmailMessage(model.Email, "إعادة تعيين كلمة المرور", mailContent);

            return Ok(new { Message = "تم إرسال رابط إعادة التعيين إلى بريدك الإلكتروني بنجاح!" });
        }

        [HttpPost("ResetPassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
                return BadRequest(new { Message = "حدث خطأ ما! برجاء المحاولة لاحقا" });

            var decodedToken = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(model.Token);
            var normalToken = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ResetPasswordAsync(user, normalToken, model.NewPassword);

            if(result.Succeeded)
                return Ok(new { Message = "تم إعادة تعيين كلمة المرور بنجاح! يمكنك تسجيل الدخول الآن." });

            return BadRequest(result.Errors);
        }

        private async Task<string> GenerateToken(ApplicationUser user)
        {
            var userClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.FullName),
                new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                userClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));

            var token = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(userClaims),
                Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["Jwt:DurationInMinutes"])),
                Issuer = _config["Jwt:Issuer"],
                Audience = _config["Jwt:Audience"],
                SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(token);

            return tokenHandler.WriteToken(securityToken);

        }

        private string GenerateRefreshToken()
        {
            var randomNumbers = new Byte[64];
            var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumbers);
            return Convert.ToBase64String(randomNumbers);
        }

        private ClaimsPrincipal GetClaimsFromExpiryToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"])),
                ValidateLifetime = false,
            };

            var tokenHandlr = new JwtSecurityTokenHandler();
            var principle = tokenHandlr.ValidateToken(token, tokenValidationParameters, out SecurityToken validationToken);

            if(validationToken is not JwtSecurityToken validationToken2 || 
                !validationToken2.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase)
                )
            {
                throw new SecurityTokenException("توكن غير صالح");
            }

            return principle;
        }
    }
}
