using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace SR_ARP
{

    class Program
    {

        double PCFreq = 0.0;
        __int64 CounterStart = 0;

        void StartCounter()
        {
            LARGE_INTEGER li;
            if (!QueryPerformanceFrequency(&li))
                std::cout << "QueryPerformanceFrequency failed!\n";

            PCFreq = double(li.QuadPart) / 1000000.0;

            QueryPerformanceCounter(&li);
            CounterStart = li.QuadPart;
        }
        double GetCounter()
        {
            LARGE_INTEGER li;
            QueryPerformanceCounter(&li);
            return double(li.QuadPart - CounterStart) / PCFreq;
        }

        [DllImport("IPHLPAPI.DLL", ExactSpelling = true)]
        public static extern int SendARP(uint DestIP, uint SrcIP,
                                 byte[] pMacAddr, ref uint PhyAddrLen);
        static void Main(string[] args)
        {
            byte[] arpRes = new byte[6];
            uint macAddrLen = 6;
            byte[] arr = { 192, 168, 127, 182 };
            if (SendARP(BitConverter.ToUInt32(arr, 0) , 0, arpRes, ref macAddrLen) == 0)
                Console.WriteLine("HUGE DUB");
            else
                Console.WriteLine("Sad G");
        }

        public static string GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
    }


}
