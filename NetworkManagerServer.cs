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
        try
        {
            bool ending = false;
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
            TcpClient client = server.AcceptTcpClient();
            // You could also use server.AcceptSocket() here.
            Console.WriteLine("Connected!");


            // Get a stream object for reading and writing
            NetworkStream networkStream = client.GetStream();


            byte[] host = Encoding.UTF8.GetBytes(Dns.GetHostName());
            
            networkStream.WriteCommand(CommandsArr.Host, host);

                

            while (true)
            {
                Thread.Sleep(100);
                byte command;
                if (networkStream.DataAvailable)
                {
                    command = encrypted ? networkStream.ReadCommand(ref decryptor) : networkStream.ReadCommand();
                }
                else
                {
                    command = Commands.None;
                }
                Console.WriteLine($"Received command: {command}");
                if (files.Count > 0 && canSend && encrypted)
                {
                    string filePath = files[0];
                    networkStream.WriteCommand(CommandsArr.FileSend, ref encryptor);
                    networkStream.WriteFile(filePath, ref encryptor, ref aes);
                    
                    sent.Add(filePath);
                    files.Remove(filePath);
                    if(files.Count == 0)
                    {
                        ending = true;
                    }
                }
                else if (ending && !networkStream.DataAvailable)
                {
                    //TODO: check encrypted?
                    networkStream.WriteCommand(CommandsArr.End, ref encryptor);
                    Console.WriteLine("send end");
                    ending = false;
                }
                else if(command != Commands.Host)
                {
                    if(files.Count > 0 && sendSync && encrypted)
                    {
                        networkStream.WriteCommand(CommandsArr.SyncRequest, ref encryptor);
                        sendSync = false;
                    }
                    else
                    {
                        try
                        {
                            if (encrypted)
                                networkStream.WriteCommand(CommandsArr.None, ref encryptor);
                            else
                                networkStream.WriteCommand(CommandsArr.None);
                        }
                        catch
                        {
                            Console.WriteLine("shut");
                            Thread.Sleep(100);
                        }
                    }
                }
                

                switch (command)
                {
                    case Commands.Host: //host
                        byte[] data = networkStream.ReadData();
                        string remoteHostname = Encoding.UTF8.GetString(data, 0, data.Length);
                        Console.WriteLine($"hostname {remoteHostname}");

                        //https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
                        bool shouldGenerateKeys = LoadKeys(remoteHostname, ref decryptor, ref encryptor);
                        if (shouldGenerateKeys)
                        {
                            GenerateRsaKeys(ref networkStream, ref decryptor, ref encryptor, remoteHostname);
                        }
                        
                        Console.WriteLine($"{encryptor.ToXmlString(false)}");
                        Console.WriteLine("writing");
                        
                        GenerateAesKey(ref networkStream, ref decryptor, ref decryptor, ref aes);

                        encrypted = true;
                        Console.WriteLine("encrypted");
                        
                        (bool exists, files) = (Tuple<bool, List<string>>)NetworkManagerCommon.FileManager.Get("GetSyncSongs").Run( remoteHostname );
                        if (!exists)
                        {
                            
                            NetworkManagerCommon.FileManager.Get("AddSyncTarget").Run( remoteHostname );
                            bool x = true;
                            if (x) // show some prompt if and which files to send
                            {
                                //TODO: Stupid! Need to ask before starting connection
                                NetworkManagerCommon.FileManager.Get("GetSongs").Run();
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
                        //TODO: finish
                        break;
                    case Commands.SyncAccepted://accepted
                        canSend = true;
                        break;
                    case Commands.SyncInfoRequest://info
                        //get data
                        string json = JsonConvert.SerializeObject(files);
                        Console.WriteLine(json);
                        byte[] msg = Encoding.UTF8.GetBytes(json);
                        networkStream.WriteCommand(CommandsArr.SyncInfo, msg, ref encryptor, ref aes);
                        break;
                    case Commands.SyncRejected://denied
                        Console.WriteLine("Sync was denied");
                        //TODO: finish
                        break;
                    case Commands.FileSend: //file
                        int i = (int)NetworkManagerCommon.FileManager.Get("GetAvailableFile").Run( "receive" );
                        string root = AppContext.BaseDirectory;
                        string path = $"{root}/tmp/receive{i}.mp3";
                        
                        networkStream.ReadFile(path, ref decryptor, ref aes);

                        //TODO: refactor method of calling file manager to be actually readable
                        //TODO: move to song objects
                        //TODO: offload to FileManager
                        MethodInfo? sanitize = NetworkManagerCommon.FileManager.Get("Sanitize");
                        string name = (string)sanitize.Run(path);
                        string artist = (string)NetworkManagerCommon.FileManager.Get("GetAlias").Run( sanitize.Run( ((string[])NetworkManagerCommon.FileManager.Get("GetSongArtist").Run( path ))[0] ) );
                        string unAlbum = (string)NetworkManagerCommon.FileManager.Get("GetSongAlbum").Run( path );
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
                            string album = (string)sanitize.Run(unAlbum);
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
                            if (encrypted)
                                networkStream.WriteCommand(CommandsArr.End, ref encryptor);
                            else
                                networkStream.WriteCommand(CommandsArr.End);
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

    private static bool LoadKeys(string remoteHostname, ref RSACryptoServiceProvider decryptor, ref RSACryptoServiceProvider encryptor)
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

    private static void SaveKeys(string remoteHostname, byte[] pubKeyByteRec)
    {
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

    private static void GenerateRsaKeys(ref NetworkStream networkStream, ref RSACryptoServiceProvider decryptor, ref RSACryptoServiceProvider encryptor, string remoteHostname)
    {
        (string pubKeyString, RSAParameters privKey) = NetworkManagerCommon.CreateKeyPair();
        decryptor.ImportParameters(privKey);
        byte[] data = Encoding.UTF8.GetBytes(pubKeyString);
        
        networkStream.WriteCommand(CommandsArr.RsaExchange, data);
        
        Console.WriteLine($"Written {data.Length}");
        
        while (!networkStream.DataAvailable)
            Thread.Sleep(10);
        
        (byte command, byte[] pubKeyByteRec) = networkStream.ReadCommandCombined();
        Console.WriteLine($"command for enc {command}");
        
        if (command != Commands.RsaExchange)
            throw new Exception("wrong order to establish cypher");
        
        encryptor.FromXmlString(Encoding.UTF8.GetString(pubKeyByteRec, 0, pubKeyByteRec.Length));
        //Console.WriteLine($"{decryptor.ToXmlString(true)}\n{encryptor.ToXmlString(false)}");
        SaveKeys(remoteHostname, pubKeyByteRec);
    }

    private static void GenerateAesKey(ref NetworkStream networkStream, ref RSACryptoServiceProvider decryptor, ref RSACryptoServiceProvider encryptor, ref Aes aes)
    {
        aes.KeySize = 256;
        aes.GenerateKey();
        networkStream.WriteCommand(CommandsArr.AesSend, aes.Key, ref encryptor);

        Console.WriteLine("waiting");
        while (!networkStream.DataAvailable)
        {
            Thread.Sleep(10);
        }
                        
        byte command = networkStream.ReadCommand(ref decryptor);
        Console.WriteLine($"command for AES {command}");

        if (command != Commands.AesReceived)
        {
            throw new Exception("wrong order to establish cypher AES");
        }
    }
}