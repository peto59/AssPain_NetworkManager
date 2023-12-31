using System.IO.IsolatedStorage;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Serialization;
using AssPain_FileManager;
using Newtonsoft.Json;

namespace AssPain_NetworkManager;

internal static class ReadExtensions
{
    /// <summary>
    /// Ensures correct number of <see cref="byte"/>s is read and waits for more if not
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="length">number of <see cref="byte"/>s to read from <paramref name="stream"/></param>
    /// <returns> <see cref="T:byte[]" /> of specified <paramref name="length"/></returns>
    private static byte[] SafeRead(this NetworkStream stream, int length)
    {
        byte[] data = new byte[length];
        int offset = 0;
        while (length > 0)
        {
            while (!stream.DataAvailable)
            {
                Thread.Sleep(10);
            }
            int read = stream.Read(data, offset, length);
            length -= read;
            offset += read;
        }
        return data;
    }
    
    /// <summary>
    /// Ensures correct number of <see cref="byte"/>s is read and waits for more if not
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="length">number of <see cref="byte"/>s to read from <paramref name="stream"/></param>
    /// <returns> <see cref="T:byte[]" /> of specified <paramref name="length"/></returns>
    private static byte[] SafeRead(this IsolatedStorageFileStream stream, int length)
    {
        byte[] data = new byte[length];
        int offset = 0;
        while (length > 0)
        {
            int read = stream.Read(data, offset, length);
            offset += read;
            length -= offset;
        }

        return data;
    }

    /// <summary>
    /// Ensures correct number of <see cref="byte"/>s is read and waits for more if not
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="length">number of <see cref="byte"/>s to read from <paramref name="stream"/></param>
    /// <param name="networkStream">stream from which crypto stream reads</param>
    /// <returns> <see cref="T:byte[]" /> of specified <paramref name="length"/></returns>
    private static byte[] SafeRead(this CryptoStream stream, int length, ref NetworkStream networkStream)
    {
        byte[] data = new byte[length];
        int offset = 0;
        while (length > 0)
        {
            while (!networkStream.DataAvailable)
            {
                Thread.Sleep(10);
#if DEBUG
                Console.WriteLine("waiting for data");
#endif
            }
            int read = stream.Read(data, offset, length);
#if DEBUG
            Console.WriteLine($"Read {read}");
#endif
            length -= read;
            offset += read;
        }

        return data;
    }
    
    /// <summary>
    /// Ensures correct number of <see cref="byte"/>s is read and waits for more if not
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="length">number of <see cref="byte"/>s to read from <paramref name="stream"/></param>
    /// <returns> <see cref="T:byte[]" /> of specified <paramref name="length"/></returns>
    internal static byte[] SafeRead(this NetworkStream stream, long length)
    {
        byte[] retArr = new byte[length];
        long totalRead = 0;
        while (length > 0)
        {
            int readThisCycle = length > int.MaxValue ? int.MaxValue : Convert.ToInt32(length);
            Array.Copy(stream.SafeRead(readThisCycle), 0, retArr, totalRead, readThisCycle);
            length -= readThisCycle;
            totalRead = +readThisCycle;
        }

        return retArr;
    }
    
    /// <summary>
    /// Ensures correct number of <see cref="byte"/>s is read and waits for more if not
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="length">number of <see cref="byte"/>s to read from <paramref name="stream"/></param>
    /// <returns> <see cref="T:byte[]" /> of specified <paramref name="length"/></returns>
    internal static byte[] SafeRead(this IsolatedStorageFileStream stream, long length)
    {
        byte[] retArr = new byte[length];
        long totalRead = 0;
        while (length > 0)
        {
            int readThisCycle = length > int.MaxValue ? int.MaxValue : Convert.ToInt32(length);
            Array.Copy(stream.SafeRead(readThisCycle), 0, retArr, totalRead, readThisCycle);
            length -= readThisCycle;
            totalRead = +readThisCycle;
        }

        return retArr;
    }

    /// <summary>
    /// Read single unencrypted <see cref="CommandsEnum"/> from <paramref name="stream"/> 
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <returns><see cref="CommandsEnum"/> read from <paramref name="stream"/></returns>
    internal static CommandsEnum ReadCommand(this NetworkStream stream)
    {
        return (CommandsEnum)stream.SafeRead(1)[0];
    }


    /// <summary>
    /// Read single encrypted <see cref="CommandsEnum"/> from stream 
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="decryptor">decryptor to be used</param>
    /// <returns><see cref="CommandsEnum"/> read from <paramref name="stream"/></returns>
    internal static (CommandsEnum command, byte[]? data, byte[]? iv, long? length) ReadCommand(this NetworkStream stream, ref RSACryptoServiceProvider decryptor)
    {
        byte[] buff = decryptor.Decrypt(stream.SafeRead(NetworkManagerCommon.RsaDataSize), true);
        if (buff.Length == 1) return ((CommandsEnum)buff[0], null, null, null);
        
        CommandsEnum command = (CommandsEnum)buff[0];
        byte[] restOfData = buff.TakeLast(buff.Length - 1).ToArray();
        if (Commands.IsLong(command))
        {
            if (restOfData.Length < 24)
                throw new Exception("HA?!");
            byte[] iv = new byte[16];
            Console.WriteLine("IV");
            Array.Copy(restOfData, iv, 16);
            long longLength = BitConverter.ToInt64(restOfData, 16);
            if (restOfData.Length <= 24) // 16 for iv, 8 for int64
                return (command, null, iv, longLength);
            Console.WriteLine("extra");
            byte[] buffer = new byte[restOfData.Length - 24]; // 16 for iv, 8 for int64
            Array.Copy(restOfData, 24, buffer, 0, buffer.Length);
            return (command, buffer, iv, longLength);
        }

        int length = BitConverter.ToInt32(restOfData);
        byte[] data = new byte[length];
        Console.WriteLine(restOfData.Length);
        Console.WriteLine(length);
        Console.WriteLine("int32");
        try
        {
            Array.Copy(restOfData, 4, data, 0, length);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
        return (command, data,  null, null);
    }

    /// <summary>
    /// Reads <see cref="CommandsEnum"/>, <see cref="long">long</see> data length and long data from <paramref name="stream"/> and decrypts them
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="decryptor">rsa decryptor to be used</param>
    /// <param name="aes">aes decryptor to be used</param>
    /// <returns><see cref="CommandsEnum"/>, <see cref="T:byte[]" /> read data</returns>
    internal static (byte command, byte[] retArr) ReadCommand(this NetworkStream stream,
        ref RSACryptoServiceProvider decryptor, ref Aes aes)
    {
        const int len = 1 + 16 + 8; //command(1), aes IV (16), encrypted data length as long(8)
        byte[] arr = stream.SafeRead(len);
        arr = decryptor.Decrypt(arr, true);
        byte command = arr[0];
        long readLength = BitConverter.ToInt64(arr, 17);
        Array.Copy(arr, 1, aes.IV, 0, 16);
        return (command, stream.ReadEncrypted(ref aes, readLength));
    }
    
    /// <summary>
    /// reads <see cref="CommandsEnum"/> and it's data
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <returns><see cref="CommandsEnum"/> and <see cref="T:byte[]" /> read data</returns>
    internal static (CommandsEnum command, byte[] data) ReadCommandCombined(this NetworkStream stream)
    {
        CommandsEnum command = stream.ReadCommand();
        return Commands.IsLong(command) ? (command, stream.ReadData(true)) : (command, stream.ReadData());
    }
    
    /// <summary>
    /// reads encrypted <see cref="CommandsEnum"/>, <see cref="T:byte[]" /> data from <paramref name="stream"/> and decrypts them if they are <see cref="int"/>, otherwise returns <see cref="Aes.IV"/> and decryption is needed to be done manually
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="decryptor">decryptor to be used</param>
    /// <returns>read <see cref="CommandsEnum"/>, <see cref="T:byte[]" /> data and <see cref="Aes.IV"/> if data is <see cref="long">long</see> based on <see cref="CommandsEnum"/> type</returns>
    internal static (byte command, byte[]? data, byte[]? iv, long? length) ReadCommandCombined(this NetworkStream stream, ref RSACryptoServiceProvider decryptor)
    {
        byte[] arr = stream.SafeRead(NetworkManagerCommon.RsaDataSize);
        arr = decryptor.Decrypt(arr, true);
        byte command = arr[0];
        if (Commands.IsLong(command))
        {
            byte[] iv = new byte[16];
            Array.Copy(arr, 1, iv, 0, 16);
            long longLength = BitConverter.ToInt64(arr, 17);
            return (command, null, iv, longLength);
        }
        int length = BitConverter.ToInt32(arr, 1);
        byte[] data = new byte[length];
        Array.Copy(arr, 5, data, 0, length);
        return (command, data, null, null);
    }

    /// <summary>
    /// reads <see cref="T:byte[]" /> data from <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="isLong">whether data is long</param>
    /// <returns>read <see cref="T:byte[]" /> data</returns>
    internal static byte[] ReadData(this NetworkStream stream, bool isLong = false)
    {
        byte[] len;
        if (isLong)
        {
            len = stream.SafeRead(8);
            long lengthLong = BitConverter.ToInt64(len, 0);
            return stream.SafeRead(lengthLong);
        }

        len = stream.SafeRead(4);
        int length = BitConverter.ToInt32(len, 0);
        return stream.SafeRead(length);
    }
    
    /// <summary>
    /// Reads encrypted <see cref="T:byte[]" /> data and decrypts them
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="decryptor">decryptor to be used</param>
    /// <returns>decrypted <see cref="T:byte[]" /></returns>
    internal static byte[] ReadData(this NetworkStream stream, ref RSACryptoServiceProvider decryptor)
    {
        return decryptor.Decrypt(stream.SafeRead(NetworkManagerCommon.RsaDataSize), true);
    }
    
    
    /// <summary>
    /// Reads encrypted <see cref="long">long</see> <see cref="T:byte[]" /> data and decrypts them
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="decryptor">decryptor to be used</param>
    /// <param name="aes">aes to decrypt with</param>
    /// <returns>decrypted <see cref="T:byte[]" /></returns>
    internal static byte[] ReadData(this NetworkStream stream, ref RSACryptoServiceProvider decryptor, ref Aes aes)
    {
        byte[] buffer = decryptor.Decrypt(stream.SafeRead(NetworkManagerCommon.RsaDataSize), true);
        Array.Copy(buffer, aes.IV, 16);
        long length = BitConverter.ToInt64(buffer, 16);
        
        return stream.ReadEncrypted(ref aes, length);
        
    }

    /// <summary>
    /// Reads encrypted <see cref="long">long</see> <see cref="T:byte[]" /> data and decrypts them using  <paramref name="aes"/> assuming  <paramref name="readLength"/> is known
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="aes">aes to decrypt with</param>
    /// <param name="readLength">number of bytes to read</param>
    /// <returns>decrypted <see cref="T:byte[]" /></returns>
    internal static byte[] ReadEncrypted(this NetworkStream stream, ref Aes aes, long readLength)
    {
        byte[] retArr = new byte[readLength];
        long totalRead = 0;
        CryptoStream csDecrypt = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read, true);
        while (readLength > 0)
        {
            int readThisCycle = readLength > int.MaxValue ? int.MaxValue : Convert.ToInt32(readLength);
            Array.Copy(stream.SafeRead(readThisCycle), 0, retArr, totalRead, readThisCycle);
            readLength -= readThisCycle;
            totalRead = +readThisCycle;
        }
        csDecrypt.Dispose();
        return retArr;
    }

    /// <summary>
    /// Reads encrypted <see cref="File" /> from stream to <see cref="File" /> specified at <see cref="Path" /> (this file <see cref="File" /> be created/overwritten)
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="path">path to write to</param>
    /// <param name="decryptor">rsa decryptor to be used</param>
    /// <param name="aes">aes decryptor to be used</param>
    internal static void ReadFile(this NetworkStream stream, string path, ref RSACryptoServiceProvider decryptor,
        ref Aes aes)
    {
        const int len = 16 + 8; //aes IV (16), encrypted data length as long(8)
        byte[] arr = stream.SafeRead(len);
        arr = decryptor.Decrypt(arr, true);
        long length = BitConverter.ToInt64(arr, 16);
        if(length > 4000000000){
            throw new Exception("You can't receive files larger than 4GB on Android");
        }
        Array.Copy(arr, 1, aes.IV, 0, 16);
        using FileStream fileStream = new FileStream(path, FileMode.Create);

        CryptoStream csDecrypt = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read, true);
        long readLength = length;
        while (readLength > 0)
        {
            if (!stream.DataAvailable)
            {
                Thread.Sleep(10);
            }

            long toRead = stream.Length < readLength ? stream.Length : readLength;
            int readThisCycle = readLength > int.MaxValue ? int.MaxValue : Convert.ToInt32(toRead);
            csDecrypt.CopyTo(fileStream, readThisCycle);
            readLength -= readThisCycle;
        }
        csDecrypt.Dispose();
    }
    
    /// <summary>
    /// Reads encrypted <see cref="File" /> from stream to <see cref="File" /> specified at <see cref="Path" /> (this file <see cref="File" /> be created/overwritten)
    /// </summary>
    /// <param name="stream">stream to read from</param>
    /// <param name="path">path to write to</param>
    /// <param name="length">length of encrypted data</param>
    /// <param name="aes">aes decryptor to be used</param>
    internal static void ReadFile(this NetworkStream stream, string path, long length,
        ref Aes aes)
    {
        //TODO: check if file system supports large files
        /*if(length > 4000000000){
            throw new Exception("You can't receive files larger than 4GB on Android");
        }*/
#if DEBUG
        Console.WriteLine($"File Length: {length}");
#endif
        using FileStream fileStream = new FileStream(path, FileMode.Create);
 
        MemoryStream ms = new MemoryStream();
        while (length > 0)
        {
            int readThisCycle = length > 8096 ? 8096 : Convert.ToInt32(length);
            byte[] buffer = stream.SafeRead(readThisCycle);
            length -= readThisCycle;
            ms.Write(buffer);
        }

        ms.Seek(0, SeekOrigin.Begin);
        CryptoStream csDecrypt = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read);
        csDecrypt.CopyTo(fileStream);
        
        /*CryptoStream csDecrypt = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Read, true);
        while (length > 0)
        {
            int readThisCycle = length > 8096 ? 8096 : Convert.ToInt32(length);
#if DEBUG
            Console.WriteLine($"remaining length: {length}");
            Console.WriteLine($"read this cycle: {readThisCycle}");
#endif
            byte[] buffer = csDecrypt.SafeRead(readThisCycle, ref stream);
            fileStream.Write(buffer);
            length -= readThisCycle;
            
        }*/
        csDecrypt.Dispose();
        fileStream.Dispose();
    }
}

internal static class WriteExtensions
{
    /// <summary>
    /// Writes unencrypted <see cref="CommandsEnum" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="command"><see cref="CommandsEnum" /> to write</param>
    internal static void WriteCommand(this NetworkStream stream, byte[] command)
    {
        stream.Write(command, 0, 1);
    }

    /// <summary>
    /// Writes encrypted <see cref="CommandsEnum" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="command"><see cref="CommandsEnum" /> to write</param>
    /// <param name="encryptor">encryptor to be used</param>
    internal static void WriteCommand(this NetworkStream stream, byte[] command,
        ref RSACryptoServiceProvider encryptor)
    {
        byte[] enc = encryptor.Encrypt(command, true);
        stream.Write(enc, 0, enc.Length);
        
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="int" /> data length and <see cref="T:byte[]" /> data as one unencrypted <see cref="T:byte[]" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="command"><see cref="CommandsEnum" /> to write</param>
    /// <param name="data"><see cref="T:byte[]" />data to write</param>
    internal static void WriteCommand(this NetworkStream stream, byte[] command, byte[] data)
    {
        int len = 1 + 4 + data.Length;
        byte[] rv = new byte[len];
        Buffer.BlockCopy(command, 0, rv, 0, 1);
        Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, rv, 1, 4);
        Buffer.BlockCopy(data, 0, rv, 5, data.Length);
        stream.Write(rv, 0, len);
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="int" /> data length and <see cref="T:byte[]" /> data as one encrypted <see cref="T:byte[]" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="command"><see cref="CommandsEnum" /> to write</param>
    /// <param name="data"><see cref="T:byte[]" />data to write</param>
    /// <param name="encryptor">encryptor to be used</param>
    /// <exception cref="InvalidDataException"><see cref="RSACryptoServiceProvider" /> with key length of 2048 has max data length of 190 bytes. 5 bytes are reserved for command and data length leaving us 185 bytes for data </exception>
    internal static void WriteCommand(this NetworkStream stream, byte[] command, byte[] data,
        ref RSACryptoServiceProvider encryptor)
    {
        int len = 1 + 4 + data.Length; //command(1), data Length as int(4)
        if (len > 190)
        {
            throw new InvalidDataException("Data cannot exceed 185 bytes"); //185 == 190 - command(1 byte) - data.Length(4 bytes)
        }
        byte[] rv = new byte[len];
        Buffer.BlockCopy(command, 0, rv, 0, 1);
        Buffer.BlockCopy(BitConverter.GetBytes(data.Length), 0, rv, 1, 4);
        Buffer.BlockCopy(data, 0, rv, 5, data.Length);
        byte[] enc = encryptor.Encrypt(rv, true);
        stream.Write(enc, 0, enc.Length);
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="Aes.IV" />, encrypted <see cref="long">long</see> data length as one encrypted <see cref="T:byte[]" /> to <paramref name="stream"/>, afterwards writes <see cref="long">long</see> encrypted <see cref="T:byte[]" /> data to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="command"><see cref="CommandsEnum" /> to write</param>
    /// <param name="data">long data to write</param>
    /// <param name="encryptor">rsa encryptor to be used</param>
    /// <param name="aes">aes encryptor to be used</param>
    internal static void WriteCommand(this NetworkStream stream, byte[] command, byte[] data,
        ref RSACryptoServiceProvider encryptor, ref Aes aes)
    {
        const int len = 1 + 16 + 8; //command(1), aes IV (16), encrypted data length as long(8)
        long encryptedDataLength = data.LongLength + (16 - data.LongLength % 16);
        byte[] rv = new byte[len];
        aes.GenerateIV();
        
        Buffer.BlockCopy(command, 0, rv, 0, 1);
        Buffer.BlockCopy(aes.IV, 0, rv, 1, 16);
        Buffer.BlockCopy(BitConverter.GetBytes(encryptedDataLength), 0, rv, 17, 8);
        rv = encryptor.Encrypt(rv, true);
        stream.Write(rv, 0, rv.Length);

        CryptoStream csEncrypt = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write, true);
        csEncrypt.WriteLongData(data);
        csEncrypt.Dispose();
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="long">long</see> data length as one encrypted <see cref="T:byte[]" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="data">data to write</param>
    /// <param name="encryptor">encryptor to be used</param>
    /// <exception cref="InvalidDataException"><see cref="RSACryptoServiceProvider" /> with key length of 2048 has max data length of 190 bytes.</exception>
    internal static void WriteData(this NetworkStream stream, byte[] data,
        ref RSACryptoServiceProvider encryptor)
    {
        if (data.Length > 190)
        {
            throw new InvalidDataException("Data cannot exceed 190 bytes");
        }
        byte[] enc = encryptor.Encrypt(data, true);
        stream.Write(enc, 0, enc.Length);
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="Aes.IV" />, encrypted <see cref="long">long</see> data length as one encrypted <see cref="T:byte[]" /> to <paramref name="stream"/>, afterwards writes <see cref="long">long</see> encrypted <see cref="T:byte[]" /> data to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="data">long data to write</param>
    /// <param name="encryptor">rsa encryptor to be used</param>
    /// <param name="aes">aes encryptor to be used</param>
    internal static void WriteData(this NetworkStream stream, byte[] data,
        ref RSACryptoServiceProvider encryptor, ref Aes aes)
    {
        const int len =  16 + 8; //aes IV (16), encrypted data length as long(8)
        long encryptedDataLength = data.LongLength + (16 - data.LongLength % 16);
        byte[] rv = new byte[len];
        aes.GenerateIV();
        
        Buffer.BlockCopy(aes.IV, 0, rv, 0, 16);
        Buffer.BlockCopy(BitConverter.GetBytes(encryptedDataLength), 0, rv, 16, 8);
        rv = encryptor.Encrypt(rv, true);
        stream.Write(rv, 0, rv.Length);

        CryptoStream csEncrypt = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write, true);
        csEncrypt.WriteLongData(data);
        csEncrypt.Dispose();
    }
    
    /// <summary>
    /// Writes <see cref="CommandsEnum" />, <see cref="Aes.IV" />, encrypted <see cref="long">long</see> data length as one encrypted <see cref="T:byte[]" /> to <paramref name="stream"/>, afterwards writes serialized <see cref="List{Song}" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to write to</param>
    /// <param name="songs">list of songs to serialize</param>
    /// <param name="encryptor">rsa encryptor to be used</param>
    /// <param name="aes">aes encryptor to be used</param>
    internal static void WriteData<T>(this NetworkStream stream, List<T> songs,
        ref RSACryptoServiceProvider encryptor, ref Aes aes)
    {
        const int len =  1 + 16 + 8; //command (1), aes IV (16), encrypted data length as long(8)
        byte[] rv = new byte[len];
        aes.GenerateIV();
        
        SongJsonConverter customConverter = new SongJsonConverter(false);
        byte[] data = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(songs, customConverter));
        
        Buffer.BlockCopy(CommandsArr.SongRequestInfo, 0, rv, 0, 1);
        Buffer.BlockCopy(aes.IV, 0, rv, 1, 16);
        Buffer.BlockCopy(BitConverter.GetBytes(data.LongLength), 0, rv, 17, 8);

        rv = encryptor.Encrypt(rv, true);
        stream.Write(rv, 0, rv.Length);
        
        CryptoStream csEncrypt = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write, true);
        csEncrypt.WriteLongData(data);
        csEncrypt.Dispose();
    }

    /// <summary>
    /// Copies data from <paramref name="source"/> to <paramref name="destination"/>
    /// </summary>
    /// <param name="destination">Destination of copy</param>
    /// <param name="source">Source of copy</param>
    private static void WriteData(this Stream destination, Stream source)
    {
        if (source.CanSeek)
        {
            // Set the position of source to the beginning
            source.Seek(0, SeekOrigin.Begin);
        }
        source.CopyTo(destination);
        /*long writeLength = otherStream.Length;
        while (writeLength > 0)
        {
            int writeThisCycle = writeLength > int.MaxValue ? int.MaxValue : Convert.ToInt32(writeLength);
            otherStream.CopyTo(networkStream, writeThisCycle);
            writeLength -= writeThisCycle;
        }*/
    }
    
    

    /// <summary>
    /// Writes long <paramref name="data"/> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to be written to</param>
    /// <param name="data">data to be written</param>
    private static void WriteLongData(this Stream stream, byte[] data)
    {
        long writeLength = data.LongLength;
        long totalWritten = 0;
        while (writeLength > 0)
        {
            int writeThisCycle = writeLength > int.MaxValue ? int.MaxValue : Convert.ToInt32(writeLength);
            writeLength -= writeThisCycle;
            totalWritten += writeThisCycle;
            byte[] toBeWritten = new byte[writeThisCycle];
            Array.Copy(data, totalWritten, toBeWritten, 0, writeThisCycle);
            stream.Write(toBeWritten, 0, writeThisCycle);
        }
    }
    
    /// <summary>
    /// Encrypts and writes <see cref="File" /> to <paramref name="stream"/>
    /// </summary>
    /// <param name="stream">stream to be written to</param>
    /// <param name="path">path to <see cref="File" /> that's to be written to <paramref name="stream"/></param>
    /// <param name="encryptor">rsa encryptor to be used</param>
    /// <param name="aes">aes encryptor to be used</param>
    /// <param name="command">command to write, default is <see cref="CommandsEnum.SongSend" /></param>
    /// <param name="data">optional extra data to be written</param>
    internal static void WriteFile(this NetworkStream stream, string path,
        ref RSACryptoServiceProvider encryptor, ref Aes aes, byte[]? command = null, byte[]? data = null)
    {
        int len = 1 + 16 + 8 + (data?.Length ?? 0); //command(1), aes IV (16), encrypted data length as long(8)
        if (len > 190 )
        {
            throw new InvalidDataException("Data cannot exceed 190 bytes");
        }
        FileInfo fi = new FileInfo(path);
        //long encryptedDataLength = fi.Length + (16 - fi.Length % 16);
        long encryptedDataLength = fi.Length + 16 - (fi.Length % 16);
        byte[] rv = new byte[len];
        aes.GenerateIV();
            
        Buffer.BlockCopy(command ?? CommandsArr.SongSend, 0, rv, 0, 1);
        Buffer.BlockCopy(aes.IV, 0, rv, 1, 16);
        Buffer.BlockCopy(BitConverter.GetBytes(encryptedDataLength), 0, rv, 17, 8);
        if (data != null)
        {
            Buffer.BlockCopy(data, 0, rv, 25, data.Length);
        }
        rv = encryptor.Encrypt(rv, true);
        stream.Write(rv, 0, rv.Length);
            
            
        CryptoStream csEncrypt = new CryptoStream(stream, aes.CreateEncryptor(), CryptoStreamMode.Write, true);
        using FileStream fs = fi.Open(FileMode.Open);
        csEncrypt.WriteData(fs);
        csEncrypt.Dispose();
    }
}