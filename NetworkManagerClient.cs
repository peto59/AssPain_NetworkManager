using System.Net;
using System.Net.Sockets;
using System.Text;
using AssPain_FileManager;

namespace AssPain_NetworkManager;

internal static class NetworkManagerClient
{
    internal static void Client(IPAddress server, int port, List<Song> songsToSend)
    {
        Console.WriteLine($"Connecting to: {server}:{port}");
        TcpClient client = new TcpClient(server.ToString(), port);
        byte[] data = Encoding.ASCII.GetBytes("end");
        NetworkStream networkStream = client.GetStream();
        string remoteHostname = string.Empty;
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
            int bytes = networkStream.Read(data, 0, data.Length);
            string responseData = Encoding.ASCII.GetString(data, 0, bytes);
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
                    byte[] message = "end"u8.ToArray();
                    networkStream.Write(message, 0, message.Length);
                    networkStream.Close();
                    client.Close();
                    goto EndClient;
                //break;
                default:
                    Console.WriteLine(responseData);
                    break;
            }
        }
        EndClient:
        // Close everything.
        networkStream.Close();
        client.Close();
    }
}