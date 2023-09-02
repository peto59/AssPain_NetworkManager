using AssPain_FileManager;
using Newtonsoft.Json;

namespace AssPain_NetworkManager;

public class main
{
    static void Main(string[] args)
    {
        //TODO: move to main program
        if (!Directory.Exists(FileManager.MusicFolder))
        {
#if DEBUG
            MyConsole.WriteLine("Creating " + $"{FileManager.MusicFolder}");
#endif
            if (FileManager.MusicFolder != null) Directory.CreateDirectory(FileManager.MusicFolder);
        }

        if (!Directory.Exists($"{FileManager.PrivatePath}/tmp"))
        {
#if DEBUG
            MyConsole.WriteLine("Creating " + $"{FileManager.PrivatePath}/tmp");
#endif
            Directory.CreateDirectory($"{FileManager.PrivatePath}/tmp");
        }
            
        //File.Delete($"{FileManager.PrivatePath}/trusted_sync_targets.json");
        if (!File.Exists($"{FileManager.PrivatePath}/trusted_sync_targets.json"))
        {
            File.WriteAllText($"{FileManager.PrivatePath}/trusted_sync_targets.json", JsonConvert.SerializeObject(new Dictionary<string, List<Song>>()));
        }

        if (!File.Exists($"{FileManager.MusicFolder}/aliases.json"))
        {
            File.WriteAllTextAsync($"{FileManager.MusicFolder}/aliases.json", JsonConvert.SerializeObject(new Dictionary<string, string>()));

        }

        if (!File.Exists($"{FileManager.MusicFolder}/playlists.json"))
        {
            File.WriteAllTextAsync($"{FileManager.MusicFolder}/playlists.json", JsonConvert.SerializeObject(new Dictionary<string, List<string>>()));
        }
        
        DirectoryInfo di = new DirectoryInfo($"{FileManager.PrivatePath}/tmp/");

        foreach (FileInfo file in di.GetFiles())
        {
            file.Delete();
#if DEBUG
            MyConsole.WriteLine($"Deleting {file}");
#endif
        }
        
        
        
        NetworkManager.Listener();
    }
}