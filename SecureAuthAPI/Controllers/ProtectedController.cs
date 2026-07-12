using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SecureAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ProtectedController : ControllerBase
    {
        [HttpGet("GetData")]
        public IActionResult GetData()
        {
            return Ok(new { Message = "مبروك! أنت أرسلت توكن سليم وقدرت تشوف البيانات السرية دي." });
        }
    }
}
