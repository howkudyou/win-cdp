using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using Microsoft.Win32;
using PcapDotNet.Core;
using PcapDotNet.Packets;

namespace WinCDP
{
    class Program
    {
        static void Main(string[] args)
        {
            const string registryKey = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryKey))
            {
                bool foundpcap = false;
                if (key != null)
                {
                    foreach (string subkeyName in key.GetSubKeyNames())
                    {
                        using (RegistryKey subkey = key.OpenSubKey(subkeyName))
                        {
                            try
                            {
                                var name = subkey.GetValue("DisplayName").ToString();
                                if (name.IndexOf("pcap", StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    foundpcap = true;
                                }
                            }
                            catch (NullReferenceException)
                            {
                                //ignored
                            }
                        }
                    }
                }

                if (foundpcap)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("WinPcap Installed!");
                    Console.ForegroundColor = ConsoleColor.White;
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("WinPcap not Installed!");
                    Console.ForegroundColor = ConsoleColor.White;
                    Environment.Exit(99);
                }
            }

            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            string cdev = GetActiveInterfaceID();

            Console.WriteLine("Device used for sniffing: " + cdev);

            int deviceIndex = 0;
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                try
                {
                    if (device.Name.Contains(cdev))
                    {
                        deviceIndex = i;
                    }
                }
                catch (Exception)
                {

                }
            }

            PacketDevice selectedDevice = allDevices[deviceIndex];

            using (PacketCommunicator communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                Packet packet;
                do
                {
                    try
                    {
                        PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out packet);
                        switch (result)
                        {
                            case PacketCommunicatorReceiveResult.Timeout:
                                continue;
                            case PacketCommunicatorReceiveResult.Ok:
                                if (packet.Ethernet.IpV4.Protocol.ToString().Equals("180"))
                                {
                                    CDPPacket cdpPacket = new CDPPacket(packet);
                                    cdpPacket.ParseCDP();
                                    Console.WriteLine("Device ID: " + cdpPacket.devID);
                                    Console.WriteLine("Port ID: " + cdpPacket.portName);


                                    foreach (var c in cdpPacket.func)
                                    {
                                        Console.WriteLine(c);
                                    }
                                }
                                break;
                            default:
                                throw new InvalidOperationException(
                                    "The result " + result + " should never be reached here");
                        }
                    }
                    catch (Exception)
                    {
                        //ignored
                    }
                } while (true);
            }
        }

        public static string GetActiveInterfaceID()
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                var addr = ni.GetIPProperties().GatewayAddresses.FirstOrDefault();
                if (addr != null && !addr.Address.ToString().Equals("0.0.0.0"))
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                    {
                        foreach (UnicastIPAddressInformation ip in ni.GetIPProperties().UnicastAddresses)
                        {
                            if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                            {
                                if (ni.Name.IndexOf("Virtual", StringComparison.CurrentCultureIgnoreCase) < 0)
                                {
                                    return ni.Id;
                                }
                            }
                        }
                    }
                }
            }
            return null;
        }

        public static string GetPhysicalMacAdress()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("Select MACAddress, PNPDeviceID FROM Win32_NetworkAdapter WHERE MACAddress IS NOT NULL AND PNPDEVICEID IS NOT NULL");
            ManagementObjectCollection mObject = searcher.Get();

            foreach (ManagementObject obj in mObject)
            {
                string pnp = obj["PNPDeviceID"].ToString();
                if (pnp.Contains("PCI\\"))
                {
                    string mac = obj["MACAddress"].ToString();
                    mac = mac.Replace(":", string.Empty);
                    return mac;
                }
            }
            return "ERRORmAc";
        }
    }
}