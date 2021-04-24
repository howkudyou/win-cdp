using PcapDotNet.Packets;
using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace WinCDP
{
    class CDPPacket
    {
        public string devID { get; private set; }
        public string vtpDomain { get; private set; }
        public string portName { get; private set; }
        public string nativeVLAN { get; private set; }
        public string platform { get; private set; }
        public string softVer { get; private set; }
        public string hello { get; private set; }
        public string ipprefix { get; private set; }
        public string duplex { get; private set; }
        public string voipvlan { get; private set; }
        public byte v { get; private set; }
        public byte ttl { get; private set; }
        public UInt16 checksum { get; private set; }
        public CDPMessage[] data { get; private set; }
        public string addresses { get; private set; }
        public string voipVlanQuery { get; private set; }
        public string power { get; private set; }
        public string mtu { get; private set; }
        public string trustBitmap { get; private set; }
        public string untrustedCOS { get; private set; }
        public string systemName { get; private set; }
        public string systemODI { get; private set; }
        public string mgmtAddress { get; private set; }
        public string location { get; private set; }
        public string extPortId { get; private set; }
        public string powerReq { get; private set; }
        public string powerAv { get; private set; }
        public string portUnidir { get; private set; }
        public string nrgyz { get; private set; }
        public string sPOE { get; private set; }
        public List<String> func = new List<String>();

        public CDPPacket(Packet packet)
        {
            CDPMessage[] msg = null;
            int counter = 22;
            v = packet[counter++];
            ttl = packet[counter++];
            checksum = (UInt16)((UInt16)(packet[counter++] << 8) | (UInt16)(packet[counter++]));

            int i = 0;
            while (counter < packet.Length)
            {
                Array.Resize(ref msg, i + 1);
                msg[i] = new CDPMessage(counter, packet);
                counter = counter + msg[i].Size + 4;
                i++;
            }
            data = msg;
        }

        public static string ByteArrayToString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        private string HexString2Ascii(string hexString)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i <= hexString.Length - 2; i += 2)
            {
                sb.Append(Convert.ToString(Convert.ToChar(Int32.Parse(hexString.Substring(i, 2), System.Globalization.NumberStyles.HexNumber))));
            }
            return sb.ToString();
        }

        public void ParseCDP()
        {
            CDPMessage[] messages = data;

            StringBuilder sb = new StringBuilder();

            foreach (CDPMessage msg in messages)
            {
                switch (msg.Type)
                {
                    case 0x0001:
                        devID = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x0002:
                        addresses = decodeAddress("Addresses: ", msg.Data, msg.Size);
                        break;
                    case 0x0003:
                        portName = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x0004:
                        for (int i = 0; i < msg.Size; i++)
                        {
                            if (byteCmp(msg.Data[i], 0x01))
                                func.Add("Performs level 3 routing for at least one network layer protocol.");
                            if (byteCmp(msg.Data[i], 0x02))
                                func.Add("Performs level 2 transparent bridging.");
                            if (byteCmp(msg.Data[i], 0x04))
                                func.Add("Performs level 2 source-route bridging.");
                            if (byteCmp(msg.Data[i], 0x08))
                                func.Add("Performs level 2 switching.");
                            if (byteCmp(msg.Data[i], 0x10))
                                func.Add("Sends and receives packets for at least one network layer protocol.");
                            if (byteCmp(msg.Data[i], 0x20))
                                func.Add("The bridge or switch does not forward IGMP.");
                            if (byteCmp(msg.Data[i], 0x40))
                                func.Add("Provides level 1 functionality.");
                        }
                        break;
                    case 0x0005:
                        softVer = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x0006:
                        platform = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x0007:
                        ipprefix = hexDump(new String(' ', 12), msg.Data, msg.Size, 8);
                        break;
                    case 0x0008:
                        hello = hexDump(new String(' ', 17), msg.Data, msg.Size, 8);
                        break;
                    case 0x0009:
                        vtpDomain = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x000a:
                        UInt64 vlan = 0;
                        for (int i = 0; i < msg.Size; i++)
                            vlan = (vlan << 8) | msg.Data[i];
                        nativeVLAN = vlan.ToString();
                        break;
                    case 0x000b:
                        sb.Append("Duplex : ");
                        if (msg.Data[0] == 0)
                            duplex = "Half";
                        else
                            duplex = "Full";
                        break;
                    case 0x000e:
                        int count = 0;
                        for (int i = 1; i < msg.Size; i += 2)
                        {
                            int cvlan = 0;
                            count++;
                            cvlan = (msg.Data[i] << 8) | msg.Data[i + 1];
                            voipvlan = cvlan.ToString();
                        }
                        break;
                    case 0x000f:
                        voipVlanQuery = hexDump(new String(' ', 18), msg.Data, msg.Size, 8);
                        break;
                    case 0x0010:
                        power = hexDump(new String(' ', 8), msg.Data, msg.Size, 8);
                        break;
                    case 0x0011:
                        mtu = hexDump(new String(' ', 6), msg.Data, msg.Size, 8);
                        break;
                    case 0x0012:
                        trustBitmap = hexDump(new String(' ', 15), msg.Data, msg.Size, 8);
                        break;
                    case 0x0013:
                        untrustedCOS = hexDump(new String(' ', 16), msg.Data, msg.Size, 8);
                        break;
                    case 0x0014:
                        systemName = Encoding.Default.GetString(msg.Data, 0, msg.Size);
                        break;
                    case 0x0015:
                        systemODI = hexDump(new String(' ', 13), msg.Data, msg.Size, 8);
                        break;
                    case 0x0016:
                        mgmtAddress = decodeAddress("Management Address : ", msg.Data, msg.Size);
                        break;
                    case 0x0017:
                        location = hexDump(new String(' ', 11), msg.Data, msg.Size, 8);
                        break;
                    case 0x0018:
                        extPortId = hexDump(new String(' ', 19), msg.Data, msg.Size, 8);
                        break;
                    case 0x0019:
                        powerReq = hexDump(new String(' ', 18), msg.Data, msg.Size, 8);
                        break;
                    case 0x001a:
                        powerAv = hexDump(new String(' ', 17), msg.Data, msg.Size, 8);
                        break;
                    case 0x001b:
                        portUnidir = hexDump(new String(' ', 14), msg.Data, msg.Size, 8);
                        break;
                    case 0x001d:
                        nrgyz = hexDump(new String(' ', 8), msg.Data, msg.Size, 8);
                        break;
                    case 0x001f:
                        sPOE = hexDump(new String(' ', 12), msg.Data, msg.Size, 8);
                        break;
                    default:
                        break;
                }
            }
        }

        private bool byteCmp(byte a, byte b)
        {
            return b == (a & b);
        }

        private string hexDump(string t, byte[] s, int size, int bpl)
        {
            int l;
            StringBuilder sb = new StringBuilder();
            StringBuilder st = new StringBuilder();

            l = ("00) " + sb.ToString()).Length;
            int j = 0;

            for (int i = 0; i < size; i++)
            {
                if (j == 0)
                {
                    if (i != 0)
                    {
                        sb.Append((i.ToString("X2") + ") ").PadLeft(l, ' '));
                    }
                    else
                    {
                        sb.Append((i.ToString("X2") + ") "));
                    }
                    st.Clear();
                }
                else
                {
                    sb.Append(":");
                }

                sb.Append(s[i].ToString("X2"));

                if (!char.IsControl(Convert.ToChar(s[i])))
                {
                    st.Append(Convert.ToChar(s[i]).ToString());
                }
                else
                {
                    st.Append(".");
                }

                j++;

                if (j == bpl)
                {
                    j = 0;
                    sb.Append(" " + st.ToString() + "\n" + t);
                }
            }

            if (j != 0)
            {
                for (; j < bpl; j++)
                {
                    sb.Append(":--");
                    st.Append(".");
                }
                sb.Append(" " + st.ToString() + "\n");
            }


            return sb.ToString();
        }

        private string decodeAddress(string s, byte[] data, int size)
        {
            StringBuilder sb = new StringBuilder();
            int pos = 0;
            int address_count = 0;

            for (int i = 0; i < 4; i++)
            {
                address_count = address_count << 8 | data[pos++];
            }

            sb.Append(s);
            while (pos < size)
            {
                int type = data[pos++];
                int len = data[pos++];
                UInt64 protocol = 0;

                switch (type)
                {
                    case 1:
                        sb.Append("Protocol format : NLPID\n");
                        protocol = data[pos++];
                        break;
                    case 2:
                        sb.Append("Protocol format : 802.2\n");
                        for (int i = 0; i < len; i++)
                        {
                            protocol = (protocol << 8) | data[pos++];
                        }
                        break;
                    default:
                        byte[] protHex = null;
                        Array.Resize(ref protHex, len);

                        for (int i = 0; i < len; i++)
                        {
                            protHex[i] = data[pos++];
                        }
                        sb.Append(hexDump("Protocol format : Unknown ", protHex, len, 8));
                        break;
                }

                if (type != 0)
                {
                    int address_length = data[pos++] << 8 | data[pos++];
                    byte[] address = null;

                    Array.Resize(ref address, address_length);

                    for (int i = 0; i < address_length; i++)
                    {
                        address[i] = data[pos++];
                    }

                    sb.Append(new String(' ', s.Length) + nlpid2String(protocol, address, address_length) + "\n");
                }
            }
            return sb.ToString();
        }

        private string byte2IPV6(byte[] s)
        {
            IPAddress ipv6 = new IPAddress(s);

            return ipv6.ToString();
        }

        private string byte2IPV4(byte[] s)
        {
            IPAddress ipv4 = new IPAddress(s);

            return ipv4.ToString();
        }

        private string nlpid2String(UInt64 protocol, byte[] address, int address_length)
        {
            StringBuilder sb = new StringBuilder();
            int wrap = 8;
            if (address_length < 8)
            {
                wrap = address_length;
            }
            switch (protocol)
            {
                case 0x00: // NLPID_NULL
                    sb.Append(hexDump("NULL : Length : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x08: // NLPID_Q933
                    sb.Append(hexDump("Q933 : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x80: // NLPID_SNAP
                    sb.Append(hexDump("SNAP : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x81: // NLPID_CLNP
                    sb.Append(hexDump("CLPN : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x82: // NLPID_ESIS
                    sb.Append(hexDump("ESIS : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x83: // NLPID_ISIS				
                    sb.Append(hexDump("ISIS : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0x8E: // NLPID_IPV6
                    sb.Append(byte2IPV6(address));
                    sb.Append("\n");
                    break;
                case 0xB0: // NLPID_FRF9
                    sb.Append(hexDump("FRF9 : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0xB1: // NLPID_FRF12
                    sb.Append(hexDump("FRF12 : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0xC0: // NLPID_TRILL
                    sb.Append(hexDump("Trill : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0xC1: // NLPID_8021AQ			
                    sb.Append(hexDump("8021AQ : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                case 0xCC: // NLPID_IPV4
                    sb.Append(byte2IPV4(address));
                    sb.Append("\n");
                    break;
                case 0xCF: // NLPID_PPP			
                    sb.Append(hexDump("PPP : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
                default:
                    sb.Append(hexDump("Unknown type : ", address, address_length, wrap));
                    sb.Append("\n");
                    break;
            }
            return sb.ToString();
        }
    }

    public class CDPMessage
    {
        public UInt16 Type { get; private set; }
        public UInt16 Size { get; private set; }
        public Byte[] Data { get; private set; }

        public CDPMessage(int pos, Packet packet)
        {
            Byte[] d = null;

            Type = (UInt16)((UInt16)(packet[pos++] << 8) | (UInt16)(packet[pos++]));
            Size = (UInt16)((UInt16)((UInt16)(packet[pos++] << 8) | (UInt16)(packet[pos++])) - 4);

            Array.Resize(ref d, Size);
            for (int i = 0; i < Size; i++)
            {
                d[i] = packet[pos++];
            }

            Data = d;
        }
    }
}
