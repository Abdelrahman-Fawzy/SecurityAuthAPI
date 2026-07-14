using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SecureAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProtectedController : ControllerBase
    {
        [HttpGet("user-data")]
        [Authorize]
        public IActionResult GetUserData()
        {
            return Ok(new { Content = "أهلاً بك، أي مستخدم مسجل يقدر يشوف الكلام ده." });
        }

        // دالة مقفولة بالترباس! حصرياً للـ Admin فقط
        [HttpGet("admin-data")]
        [Authorize(Roles = "SuperAdmin")] // 👈 تحديد الـ Role الصارمة هنا
        public IActionResult GetAdminData()
        {
            return Ok(new { Content = "سر للغاية: أهلاً بك يا سيادة المدير (Admin) في لوحة التحكم الإدارية!" });
        }
    }
}
