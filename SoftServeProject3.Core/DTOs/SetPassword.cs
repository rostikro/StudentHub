using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class SetPassword
    {
        int Code { get; set; }  
        string Password { get; set; }
        string ConfirmPassword { get; set; }
    }
}
