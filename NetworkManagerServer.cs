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
    
    internal static void Server(TcpListener server, IPAddress targetIp, List<Song> songsToSend)
    {
        //TODO: extra variables to check if can receive files
        try
        {
            bool ending = false;
            EncryptionState encryptionState = EncryptionState.None;
            SyncRequestState syncRequestState = SyncRequestState.None;
            SongSendRequestState songSendRequestState = SongSendRequestState.None;
            string remoteHostname = string.Empty;

            RSACryptoServiceProvider encryptor = new RSACryptoServiceProvider();
            RSACryptoServiceProvider decryptor = new RSACryptoServiceProvider();
            Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            int ackCount = 0;

            List<string> files = new List<string>();
            List<string> sent = new List<string>();
            Dictionary<string, string> albumArtistPair = new Dictionary<string, string>();

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
                long? length = null;

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
                            (command, data, byte[]? iv, length) = networkStream.ReadCommand(ref decryptor);
                            if (Commands.IsLong(command))
                            {
                                if (iv == null || length == null)
                                {
                                    throw new InvalidOperationException("Received empty IV or length on long data");
                                }
                                aes.IV = iv;
                                if (!Commands.IsFileCommand(command))
                                {
                                    data = networkStream.ReadEncrypted(ref aes, (long)length);
                                }
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
                //TODO: after adding trusted sync targets copy from android

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
                        songSendRequestState = SongSendRequestState.Accepted;
                        break;
                    case CommandsEnum.SongRequestRejected:
                        songSendRequestState = SongSendRequestState.Rejected;
                        break;
                    case CommandsEnum.SyncRequest: //sync
                        //TODO: finish
                        bool x = true; //filemanager . is trusted sync target
                        if (x)
                        {
                            networkStream.WriteCommand(CommandsArr.SyncAccepted, ref encryptor);
                        }
                        else
                        {
                            networkStream.WriteCommand(CommandsArr.SyncRejected, ref encryptor);
                        }
                        break;
                    case CommandsEnum.SyncAccepted://accepted
                        syncRequestState = SyncRequestState.Accepted;
                        break;
                    case CommandsEnum.SyncRejected://denied
                        syncRequestState = SyncRequestState.Rejected;
                        break;
                    case CommandsEnum.SongSend: //file
                        //TODO: check if can receive file
                        if (length != null)
                        {
#if DEBUG
                            Console.WriteLine($"file length: {length}");
#endif
                            try
                            {
                                int songIndex = FileManager.GetAvailableFile("receive");
                                string songPath = $"{FileManager.PrivatePath}/tmp/receive{songIndex}.mp3";
                                networkStream.ReadFile(songPath, (long)length, ref aes);
                                (List<string> missingArtists, (string missingAlbum, string albumArtistPath)) =
                                    FileManager.AddSong(songPath, true);
                                foreach (string name in missingArtists)
                                {
#if DEBUG
                                    Console.WriteLine($"Missing artist: {name}");
#endif
                                    networkStream.WriteCommand(CommandsArr.ArtistImageRequest,
                                        Encoding.UTF8.GetBytes(name), ref encryptor);
                                }

                                if (!string.IsNullOrEmpty(missingAlbum))
                                {
#if DEBUG
                                    Console.WriteLine($"Missing album: {missingAlbum}");
#endif
                                    networkStream.WriteCommand(CommandsArr.AlbumImageRequest,
                                        Encoding.UTF8.GetBytes(missingAlbum), ref encryptor);
                                    albumArtistPair.TryAdd(missingAlbum, albumArtistPath);
                                }
                            }
                            catch (Exception e)
                            {
#if DEBUG
                                Console.WriteLine(e);
#endif
                            }
                            networkStream.WriteCommand(CommandsArr.Ack, ref encryptor);
                        }
                        break;
                    case CommandsEnum.ArtistImageSend:
                        if (data != null && length != null)
                        {
                            try
                            {
                                string artist = FileManager.GetAlias(Encoding.UTF8.GetString(data));
                                string artistPath = FileManager.Sanitize(artist);
                                //Directory.CreateDirectory($"{FileManager.MusicFolder}/{artistPath}");
                                int imageIndex = FileManager.GetAvailableFile("networkImage", "image");
                                string imagePath = $"{FileManager.PrivatePath}/tmp/networkImage{imageIndex}.image";
                                networkStream.ReadFile(imagePath, (long)length, ref aes);
                                string imageExtension = FileManager.GetImageFormat(imagePath);
                                string artistImagePath =
                                    $"{FileManager.MusicFolder}/{artistPath}/cover.{imageExtension.TrimStart('.')}";
                                File.Move(imagePath, artistImagePath);
                                List<Artist> artists = FileManager.StateHandler.Artists.Search(artist);
                                if (artists.Count > 1)
                                {
                                    int artistIndex = FileManager.StateHandler.Artists.IndexOf(artists[0]);
                                    FileManager.StateHandler.Artists[artistIndex] =
                                        new Artist(artists[0], artistImagePath);
                                }
                            }
                            catch (Exception e)
                            {
#if DEBUG
                                Console.WriteLine(e);
#endif
                            }
                            networkStream.WriteCommand(CommandsArr.Ack, ref encryptor);
                        }
                        break;
                    case CommandsEnum.AlbumImageSend:
                        if (data != null && length != null)
                        {
                            try
                            {
                                string album = Encoding.UTF8.GetString(data);
                                string albumPath = FileManager.Sanitize(album);
                                //Directory.CreateDirectory($"{FileManager.MusicFolder}/{albumArtistPair[album]}/{albumPath}");
                                int imageIndex = FileManager.GetAvailableFile("networkImage", "image");
                                string imagePath = $"{FileManager.PrivatePath}/tmp/networkImage{imageIndex}.image";
                                networkStream.ReadFile(imagePath, (long)length, ref aes);
                                string imageExtension = FileManager.GetImageFormat(imagePath);
                                string albumImagePath =
                                    $"{FileManager.MusicFolder}/{albumArtistPair[album]}/{albumPath}/cover.{imageExtension.TrimStart('.')}";
                                File.Move(imagePath, albumImagePath);
                                List<Album> albums = FileManager.StateHandler.Albums.Search(album);
                                if (albums.Count > 1)
                                {
                                    int albumIndex = FileManager.StateHandler.Albums.IndexOf(albums[0]);
                                    FileManager.StateHandler.Albums[albumIndex] = new Album(albums[0], albumImagePath);
                                }
                                albumArtistPair.Remove(album);
                            }
                            catch (Exception e)
                            {
#if DEBUG
                                Console.WriteLine(e);
#endif
                            }
                            networkStream.WriteCommand(CommandsArr.Ack, ref encryptor);
                        }
                        break;
                    case CommandsEnum.ArtistImageRequest:
                        break;
                    case CommandsEnum.AlbumImageRequest:
                        break;
                    case CommandsEnum.Ack:
                        ackCount++;
                        break;
                    case CommandsEnum.End: //end
                        Console.WriteLine("got end");
                        if (!ending || ackCount < 0)//if work to do
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
                        Thread.Sleep(100);
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