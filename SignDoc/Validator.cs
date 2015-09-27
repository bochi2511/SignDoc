using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SignDoc
{
    class Validator
    {
        public static bool FileExist(string filepath)
        {

            return File.Exists(filepath);
        }
    }
}
