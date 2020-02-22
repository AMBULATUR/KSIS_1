using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace KSIS_1
{

    //    Создать программу, выполняющую сканирование локальной сети и отображение информации об имеющихся в ней узлах.
    //Для каждого узла программа должна отображать MAC-адрес и имя.Программа должна также отображать MAC-адрес и имя собственного компьютера, где работает программа.
    //Рекомендации:
    //1. Предусмотреть работу в ситуации, когда активно несколько сетевых интерфейсов и компьютер подключен к нескольким сетям одновременно.
    //2. Если выполняется перебор адресов локальной сети, то извлекать диапазон адресов на основе маски подсети.
    //Контрольные вопросы:
    //1. Что такое MAC-адрес?
    //2. Какую информацию можно получить исходя из маски подсети?
    //3. Протоколы ARP/RARP.
    //4. Отличия ping и tracert.
    class IPSegment
    {
        private UInt32 _ip;
        private UInt32 _mask;
        public IPSegment(string ip, string mask)
        {
            _ip = ip.ParseIp();
            _mask = mask.ParseIp();
        }
        public UInt32 NumberOfHosts
        {
            get { return ~_mask + 1; }
        }
        public UInt32 NetworkAddress
        {
            get { return _ip & _mask; }
        }
        public UInt32 BroadcastAddress
        {
            get { return NetworkAddress + ~_mask; }
        }
        public IEnumerable<UInt32> Hosts()
        {
            for (var host = NetworkAddress + 1; host < BroadcastAddress; host++)
            {
                yield return host;
            }
        }

    }

    public static class IpHelpers
    {
        public static string ToIpString(this UInt32 value)
        {
            var bitmask = 0xff000000;
            var parts = new string[4];
            for (var i = 0; i < 4; i++)
            {
                var masked = (value & bitmask) >> ((3 - i) * 8);
                bitmask >>= 8;
                parts[i] = masked.ToString(CultureInfo.InvariantCulture);
            }
            return String.Join(".", parts);
        }

        public static UInt32 ParseIp(this string ipAddress)
        {
            var splitted = ipAddress.Split('.');
            UInt32 ip = 0;
            for (var i = 0; i < 4; i++)
            {
                ip = (ip << 8) + UInt32.Parse(splitted[i]);
            }
            return ip;
        }
    }

    class Program
    {
        [DllImport("iphlpapi.dll", ExactSpelling = true)]
        public static extern int SendARP(
        uint DestIP, uint SrcIP, byte[] pMacAddr, ref int PhyAddrLen);

        private static UInt32 ConvertIPToInt32(IPAddress pIPAddr)
        {
            byte[] lByteAddress = pIPAddr.GetAddressBytes();
            var a = BitConverter.ToUInt32(lByteAddress, 0);
            return BitConverter.ToUInt32(lByteAddress, 0);
        }
        private static UInt32 ConvertStringIPToIn32(string ip)
        {
            List<Byte> bytez = new List<Byte>();
            foreach (var item in ip.Split('.'))
            {
                bytez.Add(Convert.ToByte(item));
            }
            return BitConverter.ToUInt32(bytez.ToArray(), 0);
        }
        public static void Arp()
        {
            ProcessStartInfo prompt = new ProcessStartInfo(@"cmd.exe", @"/C arp -a");
            prompt.WindowStyle = ProcessWindowStyle.Hidden;
            prompt.RedirectStandardOutput = true;
            prompt.UseShellExecute = false;
            prompt.CreateNoWindow = true;
            Process procCommand = Process.Start(prompt);
            StreamReader Response = procCommand.StandardOutput;
            string[] NormalizeResponse = Response.ReadToEnd().Split(new[] { Environment.NewLine }, StringSplitOptions.None);
            foreach (var item in NormalizeResponse)
            {
                if (item.Contains('д') || item.Contains('И'))
                    Console.WriteLine(item);
            }
            procCommand.WaitForExit();
        }




        static void Main(string[] args)
        {

            IPGlobalProperties computerProperties = IPGlobalProperties.GetIPGlobalProperties();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            Console.WriteLine("Current Computer prop [{0}]",
                computerProperties.HostName);
            if (nics == null || nics.Length < 1)
            {
                Console.WriteLine("  No network interfaces found.");
                return;
            }


            foreach (NetworkInterface adapter in nics)
            {
                if (adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 || adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    if (adapter.OperationalStatus == OperationalStatus.Up)
                    {

                        var output = string.Join(":", Enumerable.Range(0, 6).Select(i => adapter.GetPhysicalAddress().ToString().Substring(i * 2, 2)));
                        Console.WriteLine();
                        Console.WriteLine(adapter.Description);
                        Console.WriteLine(String.Empty.PadLeft(adapter.Description.Length, '='));
                        Console.WriteLine("  Adapter Name ............................ : {0}", adapter.Name);
                        Console.WriteLine("  DNS Adress .............................. : {0}", adapter.GetIPProperties().DnsAddresses[0]);
                        Console.WriteLine("  Unicast adress .......................... : {0}", adapter.GetIPProperties().UnicastAddresses[1].Address);
                        Console.WriteLine("  Unicast adress mask ..................... : {0}", adapter.GetIPProperties().UnicastAddresses[1].IPv4Mask);
                        Console.WriteLine("  Interface type .......................... : {0}", adapter.NetworkInterfaceType);
                        Console.WriteLine("  Physical Address ........................ : {0}", output);
                        Console.WriteLine("  Operational status ...................... : {0}", adapter.OperationalStatus);
                        Console.WriteLine("  Send ARP");

                        int MacLen = adapter.GetPhysicalAddress().GetAddressBytes().Length; //https://docs.microsoft.com/ru-ru/windows/win32/api/iphlpapi/nf-iphlpapi-sendarp?redirectedfrom=MSDN
                        var Mac = adapter.GetPhysicalAddress().GetAddressBytes();
                        var Mask = ConvertIPToInt32(adapter.GetIPProperties().UnicastAddresses[1].IPv4Mask);
                        var DNSIP = ConvertIPToInt32(adapter.GetIPProperties().DnsAddresses[0]);
                        var UnicastIP = ConvertIPToInt32(adapter.GetIPProperties().UnicastAddresses[1].Address);

                        IPSegment ip = new IPSegment(Convert.ToString(adapter.GetIPProperties().DnsAddresses[0]), Convert.ToString(adapter.GetIPProperties().UnicastAddresses[1].IPv4Mask));
                        List<Task> Tasks = new List<Task>();
                        foreach (var host in ip.Hosts()) //Прозвон через ARP? 
                        {
                            
                         Tasks.Add(Task.Run(()=> SendARP(ConvertStringIPToIn32(host.ToIpString()), UnicastIP, Mac, ref MacLen)));
                        }
                        Task.WaitAll(Tasks.ToArray());
                    }
            }

            Arp(); //Вывод ARP-Table

            Console.ReadLine();
        }
    }
}
