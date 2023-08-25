using System.IO.IsolatedStorage;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using AssPain_FileManager;
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
            EncryptionState encryptionState = EncryptionState.None;
            SyncRequestState syncRequestState = SyncRequestState.None;
            SongSendRequestState songSendRequestState = SongSendRequestState.None;
            bool sendSync = true;
            string remoteHostname = string.Empty;

            RSACryptoServiceProvider encryptor = new RSACryptoServiceProvider();
            RSACryptoServiceProvider decryptor = new RSACryptoServiceProvider();
            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();

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

                

            Thread.Sleep(100);
            while (true)
            {
                CommandsEnum command;
                byte[]? data = null;

                #region Reading

                if (networkStream.DataAvailable)
                {
                    switch (encryptionState)
                    {
                        case EncryptionState.None:
                        command = networkStream.ReadCommand();
                        if (Commands.IsEncryptedOnlyCommand(command))
                            throw new InvalidOperationException("Received encrypted only command on unencrypted channel");
                        break;
                        case EncryptionState.RsaExchange:
                            (command, data) = networkStream.ReadCommandCombined();
                            if (command == CommandsEnum.RsaExchange)
                            {
                                if (data == null)
                                {
                                    throw new InvalidOperationException("Received empty public key");
                                }
                            }
                            else if (command != CommandsEnum.None)
                            {
                                throw new InvalidOperationException($"wrong order to establish cypher, required step: {CommandsEnum.RsaExchange}");
                            }
                            break;
                        case EncryptionState.AesSend:
                            throw new InvalidOperationException("Server doesn't receive aes request");
                        case EncryptionState.AesReceived:
                            (command, _, _, _) = networkStream.ReadCommand(ref decryptor);
                            if (command != CommandsEnum.AesReceived && command != CommandsEnum.None)
                            {
                                throw new InvalidOperationException($"wrong order to establish cypher, required step: {CommandsEnum.AesReceived}");
                            }
                            break;
                        case EncryptionState.Encrypted:
                            (command, data, byte[]? iv, long? length) = networkStream.ReadCommand(ref decryptor);
                            if (Commands.IsLong(command))
                            {
                                if (iv == null || length == null)
                                {
                                    throw new InvalidOperationException("Received empty IV or length on long data");
                                }
                                aes.IV = iv;
                                data = networkStream.ReadEncrypted(ref aes, (long)length);
                            }
                            break;
                        default:
                            throw new ArgumentOutOfRangeException(nameof(encryptionState));
                    }
                }
                else
                {
                    command = CommandsEnum.None;
                }

                Console.WriteLine($"Received command: {command}");
                #endregion
                

                #region Writing

                if (ending && command == CommandsEnum.None)
                {
                    if (encryptionState == EncryptionState.Encrypted)
                    {
                        networkStream.WriteCommand(CommandsArr.End, ref encryptor);
                    }
                    else
                    {
                        networkStream.WriteCommand(CommandsArr.End);
                    }
                }

                #endregion

                switch (command)
                {
                    case CommandsEnum.Host: //host
                        remoteHostname = Encoding.UTF8.GetString(networkStream.ReadData());
                        Console.WriteLine($"hostname {remoteHostname}");

                        //https://learn.microsoft.com/en-us/dotnet/standard/security/how-to-store-asymmetric-keys-in-a-key-container
                        if (NetworkManagerCommon.LoadKeys(remoteHostname, ref decryptor, ref encryptor))
                        {
                            Console.WriteLine("generating keys");
                            (string pubKeyString, RSAParameters privKey) = NetworkManagerCommon.CreateKeyPair();
                            decryptor.ImportParameters(privKey);
                            networkStream.WriteCommand(CommandsArr.RsaExchange, Encoding.UTF8.GetBytes(pubKeyString));
                            encryptionState = EncryptionState.RsaExchange;
                        }
                        else
                        {
                            networkStream.WriteCommand(CommandsArr.AesSend, aes.Key, ref encryptor);
                            encryptionState = EncryptionState.AesReceived;
                        }
                        
                        
                        //TODO: here
                        /*
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
                        */
                        break;
                    case CommandsEnum.RsaExchange:
                        if (data != null)
                        {
                            string remotePubKeyString = Encoding.UTF8.GetString(data);
                            encryptor.FromXmlString(remotePubKeyString);
                            //Console.WriteLine($"{decryptor.ToXmlString(true)}\n{encryptor.ToXmlString(false)}");
                            NetworkManagerCommon.SaveKeys(remoteHostname, data);
                            
                            networkStream.WriteCommand(CommandsArr.AesSend, aes.Key, ref encryptor);
                            encryptionState = EncryptionState.AesReceived;
                        }
                        else
                        {
                            throw new Exception("WTF?");
                        }
                        break;
                    case CommandsEnum.AesSend:
                        throw new InvalidOperationException("Server doesn't receive aes request");
                    case CommandsEnum.AesReceived:
                        encryptionState = EncryptionState.Encrypted;
                        Console.WriteLine("encrypted");
                        //TODO: here
                        ending = true;
                        break;
                    case CommandsEnum.SongRequest:
                        break;
                    case CommandsEnum.SongRequestInfoRequest://info
                        //get data
                        string json = JsonConvert.SerializeObject(files);
                        Console.WriteLine(json);
                        byte[] msg = Encoding.UTF8.GetBytes(json);
                        networkStream.WriteCommand(CommandsArr.SongRequestInfo, msg, ref encryptor, ref aes);
                        break;
                    case CommandsEnum.SongRequestInfo:
                        break;
                    case CommandsEnum.SongRequestAccepted:
                        break;
                    case CommandsEnum.SongRequestRejected:
                        break;
                    case CommandsEnum.SyncRequest: //sync
                        //TODO: finish
                        break;
                    case CommandsEnum.SyncAccepted://accepted
                        canSend = true;
                        break;
                    
                    case CommandsEnum.SyncRejected://denied
                        Console.WriteLine("Sync was denied");
                        //TODO: finish
                        break;
                    
                    case CommandsEnum.SongSend: //file
                        int i = FileManager.GetAvailableFile("receive");
                        string root = AppContext.BaseDirectory;
                        string path = $"{root}/tmp/receive{i}.mp3";
                        
                        networkStream.ReadFile(path, ref decryptor, ref aes);
                        
                        //TODO: move to song objects
                        FileManager.AddSong(path);
                        break;
                    case CommandsEnum.ImageSend:
                        break;
                    case CommandsEnum.ArtistImageRequest:
                        break;
                    case CommandsEnum.AlbumImageRequest:
                        break;
                    case CommandsEnum.End: //end
                        Console.WriteLine("got end");
                        if (files.Count > 0)//if work to do
                        {
                            Console.WriteLine("Still work to do");
                            continue;
                        }
                        try
                        {
                            if (encryptionState == EncryptionState.Encrypted)
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
                    case CommandsEnum.Wait:
                        Thread.Sleep(25);
                        break;
                    case CommandsEnum.None:
                    default: //wait or unimplemented
                        Console.WriteLine($"default: {command}");
                        Thread.Sleep(25);
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