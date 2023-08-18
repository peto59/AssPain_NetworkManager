using System.IO.IsolatedStorage;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace AssPain_NetworkManager;

internal static class NetworkManagerServer
{
    //TODO: send commands as chars
    internal static (TcpListener, int) StartServer(IPAddress ip)
    {
        int listenPort = new Random().Next(1024, 65535);
        TcpListener server;
        while (true)
        {
            try
            {
                server = new TcpListener(ip, listenPort);
                server.Start();
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
    
    internal static void Server(TcpListener server, IPAddress targetIp)
    {
        TcpClient client = server.AcceptTcpClient();
        try
        {
            // Buffer for reading data
            //Byte[] data = new Byte[256];
            byte[] recCommand = new byte[256];
            byte[] sendCommand = new byte[256];
            byte[] recLength = new byte[256];
            byte[] sendLength = new byte[256];
            bool ending = false;
            string remoteHostname = string.Empty;
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
            networkStream.Write(BitConverter.GetBytes((int)Commands.Host), 0, 4);
            networkStream.Write(BitConverter.GetBytes(host.Length), 0, 4);
            networkStream.Write(host, 0, host.Length);
            //networkStream.Write(BitConverter.GetBytes(20), 0, 4);

                

            while (true)
            {
                Thread.Sleep(100);
                Commands command = Commands.None;
                if (networkStream.DataAvailable)
                {
                    if (encrypted)
                    {
                        networkStream.Read(recCommand, 0, 256);
                        command = (Commands)BitConverter.ToInt32(decryptor.Decrypt(recCommand, true), 0);
                    }
                    else
                    {
                        networkStream.Read(recCommand, 0, 4);
                        command = (Commands)BitConverter.ToInt32(recCommand, 0);
                    }
                }
                else
                {
                    command = Commands.None;
                }
                Console.WriteLine("Received command: {0}", command);
                if (files.Count > 0 && canSend)
                {
                    string filePath = files[0];
                    FileInfo fi = new FileInfo(filePath);
                    byte[] message = File.ReadAllBytes(filePath);

                    sendCommand = BitConverter.GetBytes((int)Commands.FileSend);
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
                    sendCommand = BitConverter.GetBytes((int)Commands.End);
                    sendCommand = encryptor.Encrypt(sendCommand, true);
                    networkStream.Write(sendCommand, 0, sendCommand.Length);
                    Console.WriteLine("send end");
                    ending = false;
                }
                else
                {
                    if(command != Commands.Host)
                    {
                        if(files.Count > 0 && sendSync)
                        {
                            sendCommand = BitConverter.GetBytes((int)Commands.SyncRequest);
                            sendCommand = encryptor.Encrypt(sendCommand, true);
                            networkStream.Write(sendCommand, 0, sendCommand.Length);
                            sendSync = false;
                        }
                        else
                        {
                            try
                            {
                                sendCommand = BitConverter.GetBytes((int)Commands.None);
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
                    case Commands.Host: //host
                        networkStream.Read(recLength, 0, 4);
                        int length = BitConverter.ToInt32(recLength, 0);
                        byte[] data = new byte[length];
                        networkStream.Read(data, 0, length);
                        remoteHostname = Encoding.UTF8.GetString(data, 0, length);
                        Console.WriteLine($"hostname {remoteHostname}");

                        //https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
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
                                byte[] pubKeyByte = new byte[isoStream.Length];
                                isoStream.Read(pubKeyByte);
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

                        if (shouldGenerateKeys)
                        {
                            
                            (string pubKeyString, RSAParameters privKey) = NetworkManagerCommon.CreateKeyPair();
                            networkStream.Write(BitConverter.GetBytes((int)Commands.RsaExchange), 0, 4);
                            data = Encoding.UTF8.GetBytes(pubKeyString);
                            networkStream.Write(BitConverter.GetBytes(data.Length), 0, 4);
                            networkStream.Write(data, 0, data.Length);
                            Console.WriteLine($"Written {data.Length}");

                            while (!networkStream.DataAvailable)
                            {
                                Thread.Sleep(10);
                            }

                            networkStream.Read(recCommand, 0, 4);
                            command = (Commands)BitConverter.ToInt32(recCommand);
                            Console.WriteLine($"command for enc {command}");
                            if (command != Commands.RsaExchange)
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
                                using IsolatedStorageFile isoStore = IsolatedStorageFile.GetStore(IsolatedStorageScope.User | IsolatedStorageScope.Domain | IsolatedStorageScope.Assembly, null, null);
                                using IsolatedStorageFileStream isoStream = new IsolatedStorageFileStream($"{remoteHostname}_pubkey", FileMode.OpenOrCreate, isoStore);
                                byte[] pubKeyByte = ProtectedData.Protect(pubKeyByteRec, null, DataProtectionScope.CurrentUser);
                                isoStream.Write(pubKeyByte, 0, pubKeyByte.Length);
                                Console.WriteLine("Written pubkey");
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
                        sendCommand = BitConverter.GetBytes((int)Commands.AesSend);
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
                        command = (Commands)BitConverter.ToInt32(decryptor.Decrypt(recCommand, true), 0);
                        Console.WriteLine($"command for AES {command}");

                        if (command != Commands.AesReceived)
                        {
                            throw new Exception("wrong order to establish cypher AES");
                        }

                        encrypted = true;
                        Console.WriteLine("encrypted");
                        (bool exists, files) = (Tuple<bool, List<string>>)NetworkManager.Common.FileManager.type.GetMethod("GetSyncSongs").Invoke(NetworkManager.Common.FileManager.instance, new object[] { remoteHostname });
                        if (!exists)
                        {
                            
                            NetworkManager.Common.FileManager.type.GetMethod("AddSyncTarget").Invoke(NetworkManager.Common.FileManager.instance, new object[] { remoteHostname });
                            bool x = true;
                            if (x) // show som prompt if user wants to send files
                            {
                                NetworkManager.Common.FileManager.type.GetMethod("GetSongs").Invoke(NetworkManager.Common.FileManager.instance, null);
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
                    case Commands.SyncRequest: //sync
                        break;
                    case Commands.SyncAccepted://accepted
                        canSend = true;
                        break;
                    case Commands.SyncInfo://info
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
                    case Commands.SyncRejected://denied
                        Console.WriteLine("Sync was denied");
                        break;
                    case Commands.FileSend: //file
                        int i = (int)NetworkManager.Common.FileManager.type.GetMethod("GetAvailableFile")
                            .Invoke(NetworkManager.Common.FileManager.instance, new object[] { "receive" });
                        string root = AppContext.BaseDirectory;
                        string path = $"{root}/tmp/receive{i}.mp3";
                        byte[] recFileLength = new byte[8];
                        networkStream.Read(recFileLength, 0, 8);
                        long fileLength = BitConverter.ToInt64(recFileLength, 0);
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
                            using FileStream stream = new FileStream(path, FileMode.Append);
                            Console.WriteLine($"Writing {minus} bytes");
                            stream.Write(file, 0, minus);
                        }

                        //TODO: refactor method of calling file manager to be actually readable
                        MethodInfo? sanitize = NetworkManager.Common.FileManager.type.GetMethod("Sanitize");
                        string name = (string)sanitize.Invoke(NetworkManager.Common.FileManager.instance,new object[]{path});
                        string artist = (string)NetworkManager.Common.FileManager.type.GetMethod("GetAlias").Invoke(NetworkManager.Common.FileManager.instance, new object[]{sanitize.Invoke(NetworkManager.Common.FileManager.instance, new object[]{((string[])NetworkManager.Common.FileManager.type.GetMethod("GetSongArtist").Invoke(NetworkManager.Common.FileManager.instance, new object[] { path }))[0]})});
                        string unAlbum = (string)NetworkManager.Common.FileManager.type.GetMethod("GetSongAlbum")
                            .Invoke(NetworkManager.Common.FileManager.instance, new object[] { path });
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
                            string album = (string)sanitize.Invoke(NetworkManager.Common.FileManager.instance,new object[]{unAlbum});
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
                    case Commands.End: //end
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
                        goto EndServer;
                    //break;
                    case Commands.None:
                    default: //wait or unimplemented
                        Console.WriteLine($"default: {command}");
                        break;
                }
            }
            EndServer:
            // Shutdown and end connection
            Console.WriteLine("END");
            encryptor.Dispose();
            decryptor.Dispose();
            aes.Dispose();
            networkStream.Close();
            client.Close();
            NetworkManagerCommon.ConnectedHosts.Remove(targetIp);
            //GC.Collect();
        }
        catch (SocketException ex)
        {
            Console.WriteLine("SocketException: {0}", ex);
        }
        server.Stop();
    }
}