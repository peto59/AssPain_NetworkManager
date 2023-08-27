using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AssPain_NetworkManager;

public static class NetworkManager
{
    public static void Listener()
    {
        System.Timers.Timer aTimer = new System.Timers.Timer();
        aTimer.Interval = 20000;

        aTimer.Elapsed += delegate { NetworkManagerCommon.SendBroadcast(); };

        aTimer.AutoReset = true;

        //aTimer.Enabled = true;
        
        //NetworkManagerCommon.SendBroadcast();

        while (true)
        {
            Socket sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint iep = new IPEndPoint(IPAddress.Any, NetworkManagerCommon.BroadcastPort);
            sock.Bind(iep);
            sock.EnableBroadcast = true;
            EndPoint groupEp = iep;
            byte[] buffer = new byte[256];

            try
            {
                while (true)
                {
                    Console.WriteLine("Waiting for broadcast");
                    sock.ReceiveFrom(buffer, ref groupEp);


                    IPAddress remoteIp = ((IPEndPoint)groupEp).Address;
                    if (Enumerable.Contains(NetworkManagerCommon.ConnectedHosts, remoteIp))
                    {
                        Console.WriteLine($"Exit pls2");
                        continue;
                    }

                    string remoteHostname = Encoding.UTF8.GetString(buffer).TrimEnd('\0');
                    Console.WriteLine($"Received broadcast from {groupEp}");
                    Console.WriteLine($"re,pte hostname:  {remoteHostname}");
                
                    sock.SendTo(Encoding.UTF8.GetBytes(Dns.GetHostName()), groupEp);

                    //TODO: add to available targets. Don't connect directly, check if sync is allowed.
                    NetworkManagerCommon.ConnectedHosts.Add(remoteIp);
                    new Thread(() =>
                    {
                        if (!NetworkManagerCommon.P2PDecide(remoteIp))
                        {
                            NetworkManagerCommon.ConnectedHosts.Remove(remoteIp);
                        }
                    }).Start();
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine(e);
            }
            finally
            {
                sock.Close();
                sock.Dispose();
            }
        }
    }
}