using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security;
using System.Security.Permissions;

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
    class Scaner
    {
        bool flag = true;
        string TextFromFile { get; set; }
        DirectoryInfo Directory { get; set; }
        int errorsCount { get; set; }
        int JSCount { get; set; }
        int RMCount { get; set; }
        int RunCount { get; set; }
        string jsString = "<script>evil_script()</script>";
        string rmString = @"rm -rf %userprofile%\Documents";
        string runString = "Rundll32 sus.dll SusEntry";
        Stopwatch stopWatch = new Stopwatch();

        public Scaner(string dirName)
        {
            Directory = new DirectoryInfo(dirName);
            errorsCount = 0;
            JSCount = 0;
            RMCount = 0;
            RunCount = 0;
            if (Directory.Exists)
                Scan();
            else
                Console.WriteLine("Directory specified incorrectly");
        }

        private void Scan()
        {
            stopWatch.Start();
            List<FileInfo> fileList = Directory.GetFiles().ToList();
            var extension = string.Empty;
            for (int i = 0; i < fileList.Count; ++i)
            {
                extension = fileList[i].Extension;
                try
                {
                    using (var reader = new StreamReader(fileList[i].FullName))
                    {
                        TextFromFile = reader.ReadToEnd();
                    }
                }
                catch (Exception)
                {
                    flag = false;
                    errorsCount++;
                }
                if (flag)
                {
                    if (extension == ".js")
                    {
                        if (TextFromFile.Contains(jsString))
                            JSCount++;
                    }
                    else
                        if (TextFromFile.Contains(rmString))
                        RMCount++;
                    else
                        if (TextFromFile.Contains(runString))
                        RunCount++;
                }
                else
                    flag = true;
            }
            stopWatch.Stop();
            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}", stopWatch.Elapsed.Hours,
                stopWatch.Elapsed.Minutes, stopWatch.Elapsed.Seconds);
            Console.WriteLine("====== Scan result ======\r\nProcessed files: " + fileList.Count + "\r\nJS detects: "
                + JSCount + "\r\nrm -rf detects: " + RMCount + "\r\nRundll32 detects: " + RunCount + "\r\nErrors: "
                + errorsCount + "\r\nExection time: " + elapsedTime + "\r\n=========================");

        }
    }
}
