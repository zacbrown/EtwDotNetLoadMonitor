using System;
using Microsoft.O365.Security.ETW;

namespace EtwDotNetLoadMonitor
{
    class Program
    {
        static void Main(string[] args)
        {
            var trace = new UserTrace();
            var processProvider = new Provider("Microsoft-Windows-Kernel-Process");
            processProvider.All = 0x40; // Enable the WINEVENT_KEYWORD_IMAGE flag.
            var filter = new EventFilter(Filter.EventIdIs(5));

            filter.OnEvent += (record) =>
            {
                var dllName = record.GetUnicodeString("ImageName", "<UNKNOWN>");
                if (dllName.ToLower().EndsWith("mscoree.dll"))
                {
                    var pid = record.GetUInt32("ProcessID", 0);
                    var processName = string.Empty;

                    try { processName = System.Diagnostics.Process.GetProcessById((int)pid).ProcessName; }
                    catch (Exception) { }
                    Console.WriteLine($"{processName} (PID: {pid}) loaded .NET runtime ({dllName})");
                }
            };

            processProvider.AddFilter(filter);
            trace.Enable(processProvider);

            Console.CancelKeyPress += (sender, eventArg) =>
            {
                if (trace != null)
                {
                    trace.Stop();
                }
            };

            trace.Start();
        }
    }
}
