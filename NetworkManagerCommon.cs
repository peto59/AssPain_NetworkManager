using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace AssPain_NetworkManager;

internal class NetworkManagerCommon
{
    internal (object instance, Type type) FileManager;
    internal static IPAddress MyIp = GetLocalIpAddress();
    internal static readonly List<IPAddress> ConnectedHosts = new List<IPAddress> { { MyIp } };
    internal const int BroadcastPort = 8008;
    internal NetworkManagerCommon()
    {
        LoadFileManagerDll();
    }

    private void LoadFileManagerDll()
    {
        Assembly myAssembly = Assembly.LoadFrom("AssPain_FileManager.dll");
        FileManager.type = myAssembly.GetType("AssPain_FileManager.FileManager");
        //FileManager.instance = Activator.CreateInstance(FileManager.type);
    }
    
    internal static void P2PDecide(EndPoint groupEp, IPAddress targetIp, Socket sock)
    {
        EndPoint endPoint = groupEp;
        byte[] buffer = new byte[32];
        while (true)
        {
            int state = new Random().Next(0, 2);
            sock.SendTo(BitConverter.GetBytes(state), groupEp);
            sock.ReceiveFrom(buffer, ref endPoint);
            while (!((IPEndPoint)endPoint).Address.Equals(targetIp))
            {
                sock.ReceiveFrom(buffer, ref endPoint);
            }
            int resp = BitConverter.ToInt32(buffer);
            if (resp is not (0 or 1))
            {
                Console.WriteLine("Got invalid state in P2PDecide. Exiting!");
                return;
            }

            if (state == resp) continue;
            if (state == 0)
            {
                //server
                Console.WriteLine("Server");
                
                (TcpListener server, int listenPort) = NetworkManagerServer.StartServer(MyIp);
                sock.SendTo(BitConverter.GetBytes(listenPort), groupEp);
                new Thread(() => { NetworkManagerServer.Server(server, targetIp); }).Start();
            }
            else
            {
                //client
                Console.WriteLine("Client");
                sock.ReceiveFrom(buffer, ref groupEp);
                int sendPort = BitConverter.ToInt32(buffer);
                new Thread(() => { NetworkManagerClient.Client(((IPEndPoint)groupEp).Address, sendPort); }).Start();
            }
            return;
        }
    }
    
    // ReSharper disable once MemberCanBePrivate.Global
    public static IPAddress GetLocalIpAddress()
    {
        IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (IPAddress ip in host.AddressList)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) continue;
            Console.WriteLine($"{ip}");
            return ip;
        }
        throw new Exception("No network adapters with an IPv4 address in the system!");
    }
    // ReSharper disable once MemberCanBePrivate.Global
    public static IPAddress GetSubnetMask(IPAddress address)
    {
        foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
        {
            foreach (UnicastIPAddressInformation unicastIpAddressInformation in adapter.GetIPProperties().UnicastAddresses)
            {
                if (unicastIpAddressInformation.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                if (address.Equals(unicastIpAddressInformation.Address))
                {
                    return unicastIpAddressInformation.IPv4Mask;
                }
            }
        }
        throw new ArgumentException($"Can't find subnet mask for IP address {address}");
    }
    
    private static IPAddress GetBroadCastIp(IPAddress host, IPAddress mask)
    {
        byte[] broadcastIpBytes = new byte[4];
        byte[] hostBytes = host.GetAddressBytes();
        byte[] maskBytes = mask.GetAddressBytes();
        for (int i = 0; i < 4; i++)
        {
            broadcastIpBytes[i] = (byte)(hostBytes[i] | (byte)~maskBytes[i]);
        }
        return new IPAddress(broadcastIpBytes);
    }
    
    internal static (string pubKeyString, RSAParameters privKey) CreateKeyPair()
    {
        RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        string pubKey = csp.ToXmlString(false);
        RSAParameters privKey = csp.ExportParameters(true);
        csp.Dispose();
        return (pubKey, privKey);
            
    }
    
    internal static void SendBroadcast()
    {

        if (MyIp.ToString() != "0.0.0.0")
        {
            Console.WriteLine("My IP IS: {0}", MyIp);
            Console.WriteLine("My MASK IS: {0}", GetSubnetMask(MyIp));
            Console.WriteLine("My BROADCAST IS: {0}", GetBroadCastIp(MyIp, GetSubnetMask(MyIp)));

                
            IPAddress broadcastIp = GetBroadCastIp(MyIp, GetSubnetMask(MyIp));
            IPEndPoint destinationEndpoint = new IPEndPoint(broadcastIp, BroadcastPort);
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, 1);
            sock.ReceiveTimeout = 2000;
            byte[] buffer = new byte[256];

            int retries = 0;
            const int maxRetries = 3;

            IPEndPoint iep = new IPEndPoint(IPAddress.Any, 8008);
            EndPoint groupEp = iep;
            do
            {
                sock.SendTo(Encoding.UTF8.GetBytes(Dns.GetHostName()), destinationEndpoint);
                retries++;
                try
                {
                    sock.ReceiveFrom(buffer, ref groupEp);
                    break;
                }
                catch
                {
                    // ignored
                }
            } while (retries < maxRetries);
            if (retries == maxRetries)
            {
                sock.Close();
                Console.WriteLine("No reply");
                return;
            }


            IPAddress targetIp = ((IPEndPoint)groupEp).Address;
            string remoteHostname = Encoding.UTF8.GetString(buffer, 0, buffer.Length);

            ConnectedHosts.Add(targetIp);

            P2PDecide(groupEp, targetIp, sock);

            sock.Close();
        }
        else
        {
            Console.WriteLine("No Wifi");
        }
    }
}

internal enum Commands //: byte
{
    None = 0,
    Host = 10,
    RsaExchange = 11,
    AesSend = 12,
    AesReceived = 13,
    SyncRequest = 20,
    SyncAccepted = 21,
    SyncInfo = 22,
    SyncRejected = 23,
    FileSend = 30,
    End = 100
}