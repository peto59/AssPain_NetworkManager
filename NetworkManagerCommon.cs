using System.Collections;
using System.IO.IsolatedStorage;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace AssPain_NetworkManager;

internal static class NetworkManagerCommon
{
    internal static readonly FileManager FileManager = new FileManager();
    private static readonly IPAddress MyIp = GetLocalIpAddress();
    internal static readonly List<IPAddress> ConnectedHosts = new List<IPAddress> { MyIp };
    internal const int BroadcastPort = 8008;
    internal const int RsaDataSize = 256;
    
    internal static bool P2PDecide(EndPoint groupEp, IPAddress targetIp, ref Socket sock)
    {
        EndPoint endPoint = groupEp;
        byte[] buffer = new byte[4];
        while (true)
        {
            //TODO: change state back to random
            //int state = new Random().Next(0, 2);
            const int state = 0;
            sock.SendTo(BitConverter.GetBytes(state), groupEp);
            int maxResponseCounter = 4;
            int response;
            do
            {
                sock.ReceiveFrom(buffer, ref endPoint);
                while (!((IPEndPoint)endPoint).Address.Equals(targetIp))
                {
                    //theoretically never...
                    sock.ReceiveFrom(buffer, ref endPoint);
                }
                response = BitConverter.ToInt32(buffer);
                maxResponseCounter--;
#if DEBUG
                if (response is not (0 or 1))
                {
                    Console.WriteLine($"Got invalid state in P2PDecide: {response}");
                }
#endif
            } while (response is not (0 or 1) && maxResponseCounter > 0);
            
            if (maxResponseCounter == 0)
            {
                return false;
            }

            if (state == response) continue;
            if (state == 0)
            {
                //server
                Console.WriteLine("Server");
                
                (TcpListener server, int listenPort) = NetworkManagerServer.StartServer(MyIp);
                sock.SendTo(BitConverter.GetBytes(listenPort), groupEp);
                new Thread(() => {
                    try
                    {
                        NetworkManagerServer.Server(server, targetIp);
                    }
                    catch (Exception e)
                    {
#if DEBUG
                        Console.WriteLine(e.ToString());
#endif
                    }
                }).Start();
                return true;
            }
            //client
            Console.WriteLine("Client");
            sock.ReceiveFrom(buffer, ref groupEp);
            int sendPort = BitConverter.ToInt32(buffer);
            new Thread(() => {
                try
                {
                    NetworkManagerClient.Client(((IPEndPoint)groupEp).Address, sendPort);
                }
                catch (Exception e)
                {
#if DEBUG
                    Console.WriteLine(e.ToString());
#endif
                }
            }).Start();
            return true;
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

            IPEndPoint iep = new IPEndPoint(IPAddress.Any, BroadcastPort);
            bool processedAtLestOne = false;
            do
            {
                EndPoint groupEp = iep;
                sock.SendTo(Encoding.UTF8.GetBytes(Dns.GetHostName()), destinationEndpoint);
                retries++;
                try
                {
                    sock.ReceiveFrom(buffer, ref groupEp);
                    IPAddress targetIp = ((IPEndPoint)groupEp).Address;
                    string remoteHostname = Encoding.UTF8.GetString(buffer, 0, buffer.Length);
            
                    //TODO: add to available targets. Don't connect directly, check if sync is allowed.
                    ConnectedHosts.Add(targetIp);
                    if (!P2PDecide(groupEp, targetIp, ref sock))
                    {
                        ConnectedHosts.Remove(targetIp);
                    }
                }
                catch
                {
                    // ignored
                }
            } while (retries < maxRetries && !processedAtLestOne);
            if (retries == maxRetries)
            {
                Console.WriteLine("No reply");
            }
            sock.Close();
            sock.Dispose();
        }
        else
        {
            Console.WriteLine("No Wifi");
        }
    }
    internal static bool LoadKeys(string remoteHostname, ref RSACryptoServiceProvider decryptor, ref RSACryptoServiceProvider encryptor)
    {
        bool shouldGenerateKeys = false;
        if (OperatingSystem.IsWindows())
        {
            try
            {
                CspParameters privParam = new CspParameters
                {
                    Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore,
                    KeyContainerName = $"{remoteHostname}_privkey",
                };

                decryptor = new RSACryptoServiceProvider(privParam)
                {
                    PersistKeyInCsp = true
                };

                using IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null);
                //isoStore.DeleteFile($"{remoteHostname}_pubkey");
                if (!isoStore.FileExists($"{remoteHostname}_pubkey"))
                {
                    Console.WriteLine("pubkey doesn't exist");
                    throw new Exception("This seems to be a stupid way to handle this but it actually works and is memory safe");
                }

                using IsolatedStorageFileStream isoStream = new IsolatedStorageFileStream($"{remoteHostname}_pubkey", FileMode.Open, isoStore);
                Console.WriteLine("reading pubkey");
                byte[] pubKeyByte = isoStream.SafeRead(isoStream.Length);
                encryptor.FromXmlString(Encoding.UTF8.GetString(ProtectedData.Unprotect(pubKeyByte, null, DataProtectionScope.CurrentUser)));
            }
            catch
            {
                try
                {
                    decryptor.Dispose();
                }
                catch
                {
                    // ignored
                }

                Console.WriteLine("Generating keys");
                shouldGenerateKeys = true;

                CspParameters privParam = new CspParameters
                {
                    Flags = CspProviderFlags.UseMachineKeyStore,
                    KeyContainerName = $"{remoteHostname}_privkey",
                };

                decryptor = new RSACryptoServiceProvider(privParam)
                {
                    PersistKeyInCsp = true
                };
            }
        }else if (OperatingSystem.IsLinux())
        {

        }
        else
        {
            throw new PlatformNotSupportedException("this platform is not supported");
        }

        return shouldGenerateKeys;
    }
    
    internal static void SaveKeys(string remoteHostname, byte[] pubKeyByteRec)
    {
        if (OperatingSystem.IsWindows())
        {
            using IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null);
            using IsolatedStorageFileStream isoStream = new IsolatedStorageFileStream($"{remoteHostname}_pubkey", FileMode.OpenOrCreate, isoStore);
            byte[] pubKeyByte = ProtectedData.Protect(pubKeyByteRec, null, DataProtectionScope.CurrentUser);
            isoStream.Write(pubKeyByte, 0, pubKeyByte.Length);
        }else if (OperatingSystem.IsLinux())
        {

        }
        else
        {
            throw new PlatformNotSupportedException("this platform is not supported");
        }
    }
}

internal class FileManager
{
    // ReSharper disable once InconsistentNaming
    internal (object instance, Type type) fileManager;
    private Assembly myAssembly;
    internal bool Initialized; // false
    internal FileManager()
    {
        LoadDll();
    }
    
    // ReSharper disable once MemberCanBePrivate.Global
    internal void LoadDll()
    {
        try
        {
            //TODO: fix null reference possibility:
            myAssembly = Assembly.LoadFrom("AssPain_FileManager.dll");
            fileManager.type = myAssembly.GetType("AssPain_FileManager.FileManager");
            //FileManager.instance = Activator.CreateInstance(FileManager.type);
            Initialized = true;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    internal MethodInfo? Get(string methodName)
    {
        return fileManager.type.GetMethod(methodName);
    }

    internal Type? GetExternalClass(string className)
    {
        Type? type = myAssembly.GetType($"AssPain_FileManager.{className}");
        Type genericListType = typeof(List<>).MakeGenericType(type);

        // Instantiate the generic List<T>
        IList list = (IList)Activator.CreateInstance(genericListType);
        return type;
    }
}

internal static class FileManagerExtension
{
    internal static object? Run(this MethodInfo? method, object? data = null)
    {
        return method != null ? method.Invoke(NetworkManagerCommon.FileManager.fileManager.instance, new[] { data }) : null;
    }
}