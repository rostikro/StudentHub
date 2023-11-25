using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SoftServeProject3.Core.DTOs
{
    public class UserSearchResultModel
    {
        public int TotalCount { get; set; }
        public UserListModel[] Users { get; set; }
    }

}
