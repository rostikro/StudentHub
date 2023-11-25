using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class UserListModel
    {
        public string Username { get; set; }
        public List<string> Subjects { get; set; }
        public string Faculty { get; set; }
    }
   
}
