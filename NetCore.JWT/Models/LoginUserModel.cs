using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NetCore.JWT.Models
{
    public class LoginUserModel
    {
        public string UserName { get; set; }
        public string Password { get; set; }
    }
}
