using System.IO.IsolatedStorage;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Timers;
using Newtonsoft.Json;

namespace AssPain_NetworkManager
{
    public class NetworkManager
    {

        static IPAddress myIP = GetLocalIPAddress();
        List<IPAddress> connected = new List<IPAddress> { { myIP } };
        private (object instance, Type type) FileManager;

        public NetworkManager()
        {
            Assembly myAssembly = Assembly.LoadFrom("AssPain_FileManager.dll");
            FileManager.type = myAssembly.GetType("AssPain_FileManager.FileManager");
            //FileManager.instance = Activator.CreateInstance(FileManager.type);
        }
        
        IPAddress GetBroadCastIP(IPAddress host, IPAddress mask)
        {
            byte[] broadcastIPBytes = new byte[4];
            byte[] hostBytes = host.GetAddressBytes();
            byte[] maskBytes = mask.GetAddressBytes();
            for (int i = 0; i < 4; i++)
            {
                broadcastIPBytes[i] = (byte)(hostBytes[i] | (byte)~maskBytes[i]);
            }
            return new IPAddress(broadcastIPBytes);
        }

        public void Listener()
        {
            System.Timers.Timer aTimer = new System.Timers.Timer();
            aTimer.Interval = 20000;

            aTimer.Elapsed += SendBroadcast;

            aTimer.AutoReset = true;

            //aTimer.Enabled = true;


            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint iep = new IPEndPoint(IPAddress.Any, 8008);
            sock.Bind(iep);
            sock.EnableBroadcast = true;
            EndPoint groupEP = (EndPoint)iep;
            byte[] buffer = new byte[256];

            try
            {
                while (true)
                {
                    Console.WriteLine("Waiting for broadcast");
                    sock.ReceiveFrom(buffer, ref groupEP);


                    IPAddress target_ip = ((IPEndPoint)groupEP).Address;
                    bool isAlreadyConneted = false;
                    foreach (IPAddress ip in connected)
                    {
                        if (target_ip.Equals(ip))
                        {
                            Console.WriteLine($"Exit pls2");
                            isAlreadyConneted = true;
                        }
                    }
                    if (isAlreadyConneted)
                    {
                        continue;
                    }

                    Console.WriteLine($"Received broadcast from {groupEP}");
                    Console.WriteLine($" {Encoding.UTF8.GetString(buffer)}");

                    sock.SendTo(Encoding.UTF8.GetBytes(Dns.GetHostName()), groupEP);

                    connected.Add(target_ip);
                    
                    P2PDecide(groupEP, target_ip, sock);



                }
            }
            catch (SocketException e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                sock.Close();
            }
        }

        public void SendBroadcast(Object source = null, ElapsedEventArgs e = null)
        {

            if (myIP.ToString() != "0.0.0.0")
            {
                Console.WriteLine("My IP IS: {0}", myIP.ToString());
                Console.WriteLine("My MASK IS: {0}", GetSubnetMask(myIP).ToString());
                Console.WriteLine("My BROADCAST IS: {0}", GetBroadCastIP(myIP, GetSubnetMask(myIP)));



                int broadcastPort = 8008;
                IPAddress broadcastIp = GetBroadCastIP(myIP, GetSubnetMask(myIP));
                IPEndPoint destinationEndpoint = new IPEndPoint(broadcastIp, broadcastPort);
                Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, System.Net.Sockets.ProtocolType.Udp);
                sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, 1);
                sock.ReceiveTimeout = 2000;
                byte[] buffer = new Byte[256];

                int retries = 0;
                int maxRetries = 3;

                IPEndPoint iep = new IPEndPoint(IPAddress.Any, 8008);
                EndPoint groupEP = (EndPoint)iep;
                do
                {
                    sock.SendTo(Encoding.UTF8.GetBytes(Dns.GetHostName()), destinationEndpoint);
                    retries++;
                    try
                    {
                        sock.ReceiveFrom(buffer, ref groupEP);
                        break;
                    }
                    catch { }
                } while (retries < maxRetries);
                if (retries == maxRetries)
                {
                    sock.Close();
                    Console.WriteLine("No reply");
                    return;
                }


                IPAddress target_ip = ((IPEndPoint)groupEP).Address;
                string remoteHostname = Encoding.UTF8.GetString(buffer, 0, buffer.Length);

                connected.Add(target_ip);

                P2PDecide(groupEP, target_ip, sock);

                sock.Close();
            }
            else
            {
                Console.WriteLine("No Wifi");
            }
        }
        
        private void Server(TcpListener server, IPAddress target_ip)
        {
            TcpClient client = server.AcceptTcpClient();
            try
            {
                // Buffer for reading data
                //Byte[] data = new Byte[256];
                int command = 0;
                byte[] recCommand = new byte[256];
                byte[] sendCommand = new byte[256];
                byte[] recLength = new byte[256];
                byte[] sendLength = new byte[256];
                int length = 0;
                bool ending = false;
                string remoteHostname = String.Empty;
                bool canSend = false;
                bool encrypted = false;
                bool sendSync = true;

                RSACryptoServiceProvider encryptor = new RSACryptoServiceProvider();
                RSACryptoServiceProvider decryptor = new RSACryptoServiceProvider();
                Aes aes = Aes.Create();

                List<string> files = new List<string>();
                List<string> sent = new List<string>();

                // Enter the listening loop.
                Console.Write("Waiting for a connection... ");

                // Perform a blocking call to accept requests.
                // You could also use server.AcceptSocket() here.
                Console.WriteLine("Connected!");


                // Get a stream object for reading and writing
                NetworkStream networkStream = client.GetStream();


                byte[] host = Encoding.UTF8.GetBytes(Dns.GetHostName());

                /*IEnumerable<byte> rv = BitConverter.GetBytes(10).Concat(BitConverter.GetBytes(host.Length)).Concat(host);
                byte[] message = rv.ToArray();*/
                networkStream.Write(BitConverter.GetBytes(10), 0, 4);
                networkStream.Write(BitConverter.GetBytes(host.Length), 0, 4);
                networkStream.Write(host, 0, host.Length);
                //networkStream.Write(BitConverter.GetBytes(20), 0, 4);

                

                while (true)
                {
                    Thread.Sleep(100);
                    if (networkStream.DataAvailable)
                    {
                        if (encrypted)
                        {
                            networkStream.Read(recCommand, 0, 256);
                            command = BitConverter.ToInt32(decryptor.Decrypt(recCommand, true), 0);
                        }
                        else
                        {
                            networkStream.Read(recCommand, 0, 4);
                            command = BitConverter.ToInt32(recCommand, 0);
                        }
                    }
                    else
                    {
                        command = 0;
                    }
                    Console.WriteLine("Received command: {0}", command);
                    if (files.Count > 0 && canSend)
                    {
                        string filePath = files[0];
                        FileInfo fi = new FileInfo(filePath);
                        byte[] message = File.ReadAllBytes(filePath);

                        sendCommand = BitConverter.GetBytes(30);
                        sendCommand = encryptor.Encrypt(sendCommand, true);
                        networkStream.Write(sendCommand, 0, sendCommand.Length);

                        aes.GenerateIV();

                        sendCommand = encryptor.Encrypt(aes.IV, true);
                        networkStream.Write(sendCommand, 0, sendCommand.Length);

                        using (MemoryStream msEncrypt = new MemoryStream())
                        {
                            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                            {
                                csEncrypt.Write(message);
                            }
                            message = msEncrypt.ToArray();
                        }

                        sendLength = BitConverter.GetBytes(message.LongLength);
                        sendLength = encryptor.Encrypt(sendLength, true);
                        Console.WriteLine($"Send len {sendLength.Length}");
                        networkStream.Write(sendLength, 0, sendLength.Length);

                        networkStream.Write(message, 0, message.Length);
                        sent.Add(filePath);
                        files.Remove(filePath);
                        if(files.Count == 0)
                        {
                            ending = true;
                        }
                    }
                    else if (ending && !networkStream.DataAvailable)
                    {
                        sendCommand = BitConverter.GetBytes(100);
                        sendCommand = encryptor.Encrypt(sendCommand, true);
                        networkStream.Write(sendCommand, 0, sendCommand.Length);
                        Console.WriteLine("send end");
                        ending = false;
                    }
                    else
                    {
                        if(command != 10)
                        {
                            if(files.Count > 0 && sendSync)
                            {
                                sendCommand = BitConverter.GetBytes(20);
                                sendCommand = encryptor.Encrypt(sendCommand, true);
                                networkStream.Write(sendCommand, 0, sendCommand.Length);
                                sendSync = false;
                            }
                            else
                            {
                                try
                                {
                                    sendCommand = BitConverter.GetBytes(0);
                                    sendCommand = encryptor.Encrypt(sendCommand, true);
                                    networkStream.Write(sendCommand, 0, sendCommand.Length);
                                }
                                catch
                                {
                                    Console.WriteLine("shut");
                                    Thread.Sleep(100);
                                }
                            }
                        }
                    }

                    switch (command)
                    {
                        case 10: //host
                            networkStream.Read(recLength, 0, 4);
                            length = BitConverter.ToInt32(recLength, 0);
                            byte[] data = new byte[length];
                            networkStream.Read(data, 0, length);
                            remoteHostname = Encoding.UTF8.GetString(data, 0, length);
                            Console.WriteLine($"hostname {remoteHostname}");

                            //https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
                            bool shouldGenerateKeys = false;
                            if (OperatingSystem.IsWindows())
                            {
                                /*try
                                {
                                    CspParameters privParam = new CspParameters
                                    {
                                        Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore,
                                        KeyContainerName = $"{remoteHostname}_privkey",
                                    };

                                    decryptor = new RSACryptoServiceProvider(privParam)
                                    {
                                        PersistKeyInCsp = false
                                    };

                                    decryptor.Dispose();

                                    using (IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null))
                                    {
                                        isoStore.DeleteFile($"{remoteHostname}_pubkey");
                                    }
                                }
                                catch { }*/
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

                                    using (IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null))
                                    {
                                        //isoStore.DeleteFile($"{remoteHostname}_pubkey");
                                        if (!isoStore.FileExists($"{remoteHostname}_pubkey"))
                                        {
                                            Console.WriteLine("pubkey doesn exist");
                                            throw new Exception("This seems to be a stupid way to handle this but it actually works and is memory safe");
                                        }

                                        using (IsolatedStorageFileStream isoStream = new IsolatedStorageFileStream($"{remoteHostname}_pubkey", FileMode.Open, isoStore))
                                        {
                                            Console.WriteLine("reading pubkey");
                                            byte[] pubKeyByte = new byte[isoStream.Length];
                                            isoStream.Read(pubKeyByte);
                                            encryptor.FromXmlString(Encoding.UTF8.GetString(ProtectedData.Unprotect(pubKeyByte, null, DataProtectionScope.CurrentUser)));
                                        }
                                    }
                                }
                                catch
                                {
                                    try
                                    {
                                        decryptor.Dispose();
                                    }
                                    catch
                                    {
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

                            if (shouldGenerateKeys)
                            {
                                (string pubKeyString, RSAParameters privKey) = CreateKeyPair();
                                networkStream.Write(BitConverter.GetBytes(11), 0, 4);
                                data = Encoding.UTF8.GetBytes(pubKeyString);
                                networkStream.Write(BitConverter.GetBytes(data.Length), 0, 4);
                                networkStream.Write(data, 0, data.Length);
                                Console.WriteLine($"Written {data.Length}");

                                while (!networkStream.DataAvailable)
                                {
                                    Thread.Sleep(10);
                                }

                                networkStream.Read(recCommand, 0, 4);
                                command = BitConverter.ToInt32(recCommand);
                                Console.WriteLine($"command for enc {command}");
                                if (command != 11)
                                {
                                    throw new Exception("wrong order to establish cypher");
                                }
                                networkStream.Read(recLength, 0, 4);
                                length = BitConverter.ToInt32(recLength, 0);
                                byte[] pubKeyByteRec = new byte[length];
                                networkStream.Read(pubKeyByteRec, 0, length);
                                decryptor.ImportParameters(privKey);
                                encryptor.FromXmlString(Encoding.UTF8.GetString(pubKeyByteRec, 0, length));
                                RSAParameters pubKey = encryptor.ExportParameters(false);

                                //Console.WriteLine($"{decryptor.ToXmlString(true)}\n{encryptor.ToXmlString(false)}");

                                if (OperatingSystem.IsWindows())
                                {
                                    using (IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null))
                                    {
                                        using (IsolatedStorageFileStream isoStream = new IsolatedStorageFileStream($"{remoteHostname}_pubkey", FileMode.OpenOrCreate, isoStore))
                                        {
                                            byte[] pubKeyByte = ProtectedData.Protect(pubKeyByteRec, null, DataProtectionScope.CurrentUser);
                                            isoStream.Write(pubKeyByte, 0, pubKeyByte.Length);
                                            Console.WriteLine("Written pubkey");
                                        }
                                    }
                                }else if (OperatingSystem.IsLinux())
                                {

                                }
                                else
                                {
                                    throw new PlatformNotSupportedException("this platform is not supported");
                                }
                            }
                            Console.WriteLine($"{encryptor.ToXmlString(false)}");

                            Console.WriteLine("writing");
                            sendCommand = BitConverter.GetBytes(12);
                            sendCommand = encryptor.Encrypt(sendCommand, true);
                            networkStream.Write(sendCommand, 0, sendCommand.Length);
                            aes.KeySize = 256;
                            aes.GenerateKey();

                            Console.WriteLine("writing");
                            sendCommand = encryptor.Encrypt(aes.Key, true);
                            networkStream.Write(sendCommand, 0, sendCommand.Length);

                            Console.WriteLine("waiting");
                            while (!networkStream.DataAvailable)
                            {
                                Thread.Sleep(10);
                            }
                            networkStream.Read(recCommand, 0, 256);
                            command = BitConverter.ToInt32(decryptor.Decrypt(recCommand, true), 0);
                            Console.WriteLine($"command for AES {command}");

                            if (command != 13)
                            {
                                throw new Exception("wrong order to establish cypher AES");
                            }

                            encrypted = true;
                            Console.WriteLine("encrypted");
                            (bool exists, files) = (Tuple<bool, List<string>>)FileManager.type.GetMethod("GetSyncSongs").Invoke(FileManager.instance, new object[] { remoteHostname });
                            if (!exists)
                            {
                                FileManager.type.GetMethod("AddSyncTarget").Invoke(FileManager.instance, new object[] { remoteHostname });
                                bool x = true;
                                if (x) // show som prompt if user wants to send files
                                {
                                    FileManager.type.GetMethod("GetSongs").Invoke(FileManager.instance, null);
                                }
                                else
                                {
                                    ending = true;
                                }
                            }
                            if (files.Count == 0)
                            {
                                ending = true;
                            }
                            break;
                        case 20: //sync
                            break;
                        case 21://accepted
                            canSend = true;
                            break;
                        case 22://info
                            //get data
                            string json = JsonConvert.SerializeObject(files);
                            Console.WriteLine(json);
                            byte[] msg = Encoding.UTF8.GetBytes(json);

                            aes.GenerateIV();
                            sendLength = encryptor.Encrypt(aes.IV, true);
                            networkStream.Write(sendLength, 0, sendLength.Length);
                            Console.WriteLine($"length IV enc {sendLength.Length}");
                            Console.WriteLine($"length IV {aes.IV.Length}");

                            //encrypt data
                            using (MemoryStream msEncrypt = new MemoryStream())
                            {
                                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, aes.CreateEncryptor(), CryptoStreamMode.Write))
                                {
                                    csEncrypt.Write(msg);
                                }
                                msg = msEncrypt.ToArray();
                            }

                            //encrypted length
                            sendLength = encryptor.Encrypt(BitConverter.GetBytes(msg.Length), true);
                            networkStream.Write(sendLength, 0, sendLength.Length);
                            Console.WriteLine($"length {msg.Length}");

                            //send encrypted data
                            networkStream.Write(msg, 0, msg.Length);
                            break;
                        case 23://denied
                            Console.WriteLine("Sync was denied");
                            break;
                        case 30: //file
                            int i = (int)FileManager.type.GetMethod("GetAvailableFile")
                                .Invoke(FileManager.instance, new object[] { "receive" });
                            string root = AppContext.BaseDirectory;
                            string path = $"{root}/tmp/receive{i}.mp3";
                            byte[] recFileLength = new byte[8];
                            networkStream.Read(recFileLength, 0, 8);
                            Int64 fileLength = BitConverter.ToInt64(recFileLength, 0);
                            if (fileLength > 4000000000)
                            {
                                throw new Exception("You can't receive files larger than 4GB on Android");
                            }
                            int readLength;
                            Console.WriteLine($"File size {fileLength}");
                            while (fileLength > 0)
                            {
                                if (fileLength > int.MaxValue)
                                {
                                    readLength = int.MaxValue;
                                }
                                else
                                {
                                    readLength = Convert.ToInt32(fileLength);
                                }
                                byte[] file = new byte[readLength];
                                int minus = networkStream.Read(file, 0, readLength);
                                fileLength -= minus;
                                using (var stream = new FileStream(path, FileMode.Append))
                                {
                                    Console.WriteLine($"Writing {minus} bytes");
                                    stream.Write(file, 0, minus);
                                }
                            }

                            MethodInfo? sanitize = FileManager.type.GetMethod("Sanitize");
                            string name = (string)sanitize.Invoke(FileManager.instance,new object[]{path});
                            string artist = (string)FileManager.type.GetMethod("GetAlias").Invoke(FileManager.instance, new object[]{sanitize.Invoke(FileManager.instance, new object[]{((string[])FileManager.type.GetMethod("GetSongArtist").Invoke(FileManager.instance, new object[] { path }))[0]})});
                            string unAlbum = (string)FileManager.type.GetMethod("GetSongAlbum")
                                .Invoke(FileManager.instance, new object[] { path });
                            if (unAlbum == null)
                            {
                                Directory.CreateDirectory($"{root}/music/{artist}");
                                if (!File.Exists($"{root}/music/{artist}/{name}.mp3"))
                                {
                                    File.Move(path, $"{root}/music/{artist}/{name}.mp3");
                                }
                                else
                                {
                                    File.Delete(path);
                                }
                            }
                            else
                            {
                                string album = (string)sanitize.Invoke(FileManager.instance,new object[]{unAlbum});
                                Directory.CreateDirectory($"{root}/music/{artist}/{album}");
                                if (!File.Exists($"{root}/music/{artist}/{album}/{name}.mp3"))
                                {
                                    File.Move(path, $"{root}/music/{artist}/{album}/{name}.mp3");
                                }
                                else
                                {
                                    File.Delete(path);
                                }
                            }
                            break;
                        case 100: //end
                            Console.WriteLine("got end");
                            if (files.Count > 0)//if work to do
                            {
                                Console.WriteLine("Still work to do");
                                continue;
                            }
                            try
                            {
                                sendCommand = BitConverter.GetBytes(100);
                                sendCommand = encryptor.Encrypt(sendCommand, true);
                                networkStream.Write(sendCommand, 0, sendCommand.Length);
                                Thread.Sleep(100);
                            }
                            catch
                            {
                                Console.WriteLine("Disconnected");
                            }
                            networkStream.Close();
                            client.Close();
                            goto End;
                        //break;
                        default: //wait or uninplemented
                            Console.WriteLine($"default: {command}");
                            break;
                    }
                }
            End:
                // Shutdown and end connection
                Console.WriteLine("END");
                encryptor.Dispose();
                decryptor.Dispose();
                aes.Dispose();
                networkStream.Close();
                client.Close();
                connected.Remove(target_ip);
                //GC.Collect();
            }
            catch (SocketException ex)
            {
                Console.WriteLine("SocketException: {0}", ex);
            }
            server.Stop();
        }

        private void Client(IPAddress server, int port)
        {
            Console.WriteLine($"Connecting to: {server}:{port}");
            TcpClient client = new TcpClient(server.ToString(), port);
            byte[] data = Encoding.ASCII.GetBytes("end");
            NetworkStream networkStream = client.GetStream();
            string remoteHostname = String.Empty;
            while (true)
            {
                try
                {
                    networkStream.Write(data, 0, data.Length);
                }
                catch
                {
                    Console.WriteLine("shut");
                }
                data = new byte[256];
                String responseData = String.Empty;
                Int32 bytes = networkStream.Read(data, 0, data.Length);
                responseData = Encoding.ASCII.GetString(data, 0, bytes);
                Console.WriteLine("Received: {0}", responseData);
                switch (responseData)
                {
                    case "host":
                        bytes = networkStream.Read(data, 0, data.Length);
                        remoteHostname = Encoding.ASCII.GetString(data, 0, bytes);
                        break;
                    case "autosync":
                        //FileManager.AddSyncTarget(remoteHostname);
                        break;
                    case "file":
                        string f = $"{AppContext.BaseDirectory}/music/Mori Calliope Ch. hololive-EN/[Original Rap] DEAD BEATS - Calliope Mori holoMyth hololiveEnglish.mp3";
                        //(TcpListener receiveServer, int listenPort) = StartServer();


                        break;
                    case "end":
                        byte[] message = Encoding.ASCII.GetBytes("end");
                        networkStream.Write(message, 0, message.Length);
                        networkStream.Close();
                        client.Close();
                        goto End;
                    //break;
                    default:
                        Console.WriteLine(responseData);
                        break;
                }
            }
        End:
            // Close everything.
            networkStream.Close();
            client.Close();
        }

        private void P2PDecide(EndPoint groupEP, IPAddress target_ip, Socket sock)
        {
            int state;
            EndPoint endPoint = groupEP;
            byte[] buffer = new Byte[32];
            while (true)
            {
                //state = new Random().Next(0, 2);
                state = 0;
                sock.SendTo(BitConverter.GetBytes(state), groupEP);
                sock.ReceiveFrom(buffer, ref endPoint);
                while (!((IPEndPoint)endPoint).Address.Equals(target_ip))
                {
                    sock.ReceiveFrom(buffer, ref endPoint);
                }
                int resp = BitConverter.ToInt32(buffer);
                if (resp == 0 || resp == 1)
                {
                    if (state != resp)
                    {
                        if (state == 0)
                        {
                            //server
                            Console.WriteLine("Server");
                            (TcpListener server, int listenPort) = StartServer(myIP);
                            sock.SendTo(BitConverter.GetBytes(listenPort), groupEP);
                            new Thread(() => { Server(server, target_ip); }).Start();
                        }
                        else
                        {
                            //client
                            Console.WriteLine("Client");
                            sock.ReceiveFrom(buffer, ref groupEP);
                            int sendPort = BitConverter.ToInt32(buffer);
                            new Thread(() => { Client(((IPEndPoint)groupEP).Address, sendPort); }).Start();
                        }
                        return;
                    }
                }
            }
        }

        public static (TcpListener, int) StartServer(IPAddress ip)
        {
            int listenPort = new Random().Next(1024, 65535);
            TcpListener server;
            while (true)
            {
                try
                {
                    server = new TcpListener(ip, listenPort);
                    server.Start();
                    MemoryStream memoryStream = new MemoryStream();
                    break;
                }
                catch
                {
                    listenPort = new Random().Next(1024, 65535);
                }
            }
            Console.WriteLine(listenPort);
            return (server, listenPort);
        }

        public static IPAddress GetLocalIPAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    Console.WriteLine($"{ip}");
                    return ip;
                }
            }
            throw new Exception("No network adapters with an IPv4 address in the system!");
        }
        public static IPAddress GetSubnetMask(IPAddress address)
        {
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation unicastIPAddressInformation in adapter.GetIPProperties().UnicastAddresses)
                {
                    if (unicastIPAddressInformation.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (address.Equals(unicastIPAddressInformation.Address))
                        {
                            return unicastIPAddressInformation.IPv4Mask;
                        }
                    }
                }
            }
            throw new ArgumentException(string.Format("Can't find subnetmask for IP address '{0}'", address));
        }

        private (string pubKeyString, RSAParameters privKey) CreateKeyPair()
        {
            RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
            string pubKey = csp.ToXmlString(false);
            RSAParameters privKey = csp.ExportParameters(true);
            csp.Dispose();
            return (pubKey, privKey);
            
        }
    }
}
