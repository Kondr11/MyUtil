using System;

namespace Scan_util
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                Scaner scaner = new Scaner(args[0]);
            }
            else
                Console.WriteLine("Enter directory name");
        }
    }
}
