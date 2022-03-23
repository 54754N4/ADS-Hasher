using Microsoft.Win32.SafeHandles;
using System;
using System.Linq;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static ADS_Hasher.Parser;

namespace ADS_Hasher
{
    class Program
    {

        static void Main(string[] args)
        {
            Arguments flags = Parse(args);
            if (flags == Arguments.None || flags.HasFlag(Arguments.Help)) 
            {
                Console.WriteLine(HelpMessage());
                return;
            }
            string filepath = GetFilepath(args);
            if (filepath == null)
            {
                Console.WriteLine("Please give filepath for hash.");
                return;
            }
            Func<string, string, string> hasher = flags.HasFlag(Arguments.NoADS) ? HashFile : HashADS;
            string name, hash;
            for (int i=MIN; i<=MAX; i++)
            {
                Arguments current = ArgAt(i);
                if (flags.HasFlag(current))
                {
                    name = ArgName(current);
                    hash = hasher.Invoke(name, filepath);
                    Console.WriteLine($"{name}:\t{hash}");
                }
            }
        }

        private static string HashADS(string name, string filename)
            => Hasher.HashOverall(name, Hasher.HashADS(name, filename)).ToHashString();

        private static string HashFile(string name, string filename)
            => Hasher.HashFile(name, filename).ToHashString();

        public static string HelpMessage()
            => new StringBuilder()
                .AppendLine("Usage: hasher.exe <OPTIONS> <file>")
                .AppendLine("Options:")
                .AppendLine("\t-h,--help\tPrints this help message")
                .AppendLine("\t-n,--no-ads\tHashes default stream only")
                .AppendLine("\t-md5\t\tIncludes MD5 hash")
                .AppendLine("\t-sha1\t\tIncludes SHA1 hash")
                .AppendLine("\t-sha256\t\tIncludes SHA256 hash")
                .AppendLine("\t-sha384\t\tIncludes SHA384 hash")
                .AppendLine("\t-sha512\t\tIncludes SHA512 hash")
                .ToString();
    }

    internal static class Parser
    {
        [Flags]
        public enum Arguments
        {
            None = 0,
            NoADS = 1 << 0,
            Help = 1 << 1,
            MD5 = 1 << 2,
            SHA1 = 1 << 3,
            SHA256 = 1 << 4,
            SHA384 = 1 << 5,
            SHA512 = 1 << 6
        }

        public static int MIN = 2, MAX = 6; // Range of powers that map to hash algorithm

        public static Arguments Parse(params string[] args)
        {
            Arguments flags = Arguments.None;
            foreach (string arg in args)
            {
                switch (arg)
                {
                    case "-n":
                    case "--no-ads":
                        flags |= Arguments.NoADS;
                        break;
                    case "-h":
                    case "--help":
                        flags |= Arguments.Help;
                        break;
                    case "-md5": 
                        flags |= Arguments.MD5;
                        break;
                    case "-sha1":
                        flags |= Arguments.SHA1;
                        break;
                    case "-sha256":
                        flags |= Arguments.SHA256;
                        break;
                    case "-sha384":
                        flags |= Arguments.SHA384;
                        break;
                    case "-sha512":
                        flags |= Arguments.SHA512;
                        break;
                }
            }
            return flags;
        }

        public static Arguments ArgAt(int i)
            => i >= MIN && i <= MAX ? (Arguments)(1 << i) : Arguments.None;

        public static string ArgName(Arguments arg)
            => arg switch
            {
                Arguments.MD5 => "md5",
                Arguments.SHA1 => "sha1",
                Arguments.SHA256 => "sha256",
                Arguments.SHA384 => "sha384",
                Arguments.SHA512 => "sha512",
                _ => null,
            };
        public static string GetFilepath(params string[] args) 
        {
            foreach (string arg in args)
                if (!arg.StartsWith("-"))
                    return arg;
            return null;
        }
    }

    public static class Hasher
    {
        private const string DELIMITER = ".:|:.";
        public static readonly Dictionary<string, Func<HashAlgorithm>> HASHES = new()
        {
            { "md5",  MD5.Create },
            { "sha1", SHA1.Create },
            { "sha256", SHA256.Create },
            { "sha384", SHA384.Create },
            { "sha512", SHA512.Create },
        };

        /* The concatenation of hashes should be an injective function to prevent
         * hash("ab"+"c") == hash("a"+"bc"). So we prepend a delimiter with every
         * concatenated hash.
         * Reference: https://crypto.stackexchange.com/a/55172/100780
         */
        public static byte[] HashOverall(string name, byte[][] hashes)
        {
            if (!HASHES.ContainsKey(name))
                throw new ArgumentException($"{name} hash algorithm is not supported");
            var sb = new StringBuilder();
            foreach (var hash in hashes)
                sb.Append($"{hash.ToHashString()}{DELIMITER}");
            using var hasher = HASHES[name].Invoke();
            return hasher.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
        }

        public static byte[][] HashADS(string name, string file)
        {
            var streamNames = AlternateDataStreams.GetStreams(new FileInfo(file));
            byte[][] hashes = new byte[streamNames.Count()][];
            int i = 0;
            foreach (var streamName in streamNames)
                hashes[i++] = HashFile(name, $"{file}{streamName}");
            return hashes;
        }

        public static byte[] HashFile(string name, string filepath)
        {
            if (!HASHES.ContainsKey(name))
                throw new ArgumentException($"{name} hash algorithm is not supported");
            using var hasher = HASHES[name].Invoke();
            using var stream = File.OpenRead(filepath);
            return hasher.ComputeHash(stream);
        }

        public static string ToHashString(this byte[] bytes)
            => BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    /**
     * Reference: https://docs.microsoft.com/en-us/archive/msdn-magazine/2006/january/net-matters-iterating-ntfs-streams
     */
    public sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeFindHandle() : base(true) { }
        protected override bool ReleaseHandle()
        {
            return FindClose(handle);
        }
        
        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindClose(IntPtr handle);
    }

    public class AlternateDataStreams
    {
        private const int ERROR_HANDLE_EOF = 38;
        private enum StreamInfoLevels { FindStreamInfoStandard = 0 }

        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern SafeFindHandle FindFirstStreamW(
            string lpFileName,
            StreamInfoLevels InfoLevel,
            [In, Out, MarshalAs(UnmanagedType.LPStruct)] WIN32_FIND_STREAM_DATA lpFindStreamData,
            uint dwFlags
        );
        
        [DllImport("kernel32.dll", ExactSpelling = true, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FindNextStreamW(
            SafeFindHandle hndFindFile,
            [In, Out, MarshalAs(UnmanagedType.LPStruct)] WIN32_FIND_STREAM_DATA lpFindStreamData
        );
        
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private class WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }
        
        public static IEnumerable<string> GetStreams(FileInfo file)
        {
            if (file == null)
                throw new ArgumentNullException(nameof(file));
            WIN32_FIND_STREAM_DATA findStreamData = new();
            SafeFindHandle handle = FindFirstStreamW(file.FullName, StreamInfoLevels.FindStreamInfoStandard, findStreamData, 0);
            if (handle.IsInvalid)
                throw new Win32Exception();
            try {
                do {
                    yield return findStreamData.cStreamName;
                } while (FindNextStreamW(handle, findStreamData));
                int lastError = Marshal.GetLastWin32Error();
                if (lastError != ERROR_HANDLE_EOF)
                    throw new Win32Exception(lastError);
            } finally {
                handle.Dispose();
            }
        }
    }

    /**
     * Simplifies reading from a buffer
     */
    public static class BufferedReader
    {
        public const int DEFAULT_BUFFER_SIZE = 4096;

        public static void ReadBuffered(this Stream stream, Action<byte[], int> consumer)
            => ReadBuffered(stream, DEFAULT_BUFFER_SIZE, consumer);

        public static void ReadBuffered(this Stream stream, int bufferSize, Action<byte[], int> consumer)
        {
            var buffer = new byte[bufferSize];
            while (true)
            {
                int read = stream.Read(buffer, 0, bufferSize);
                if (read == 0)
                    break;
                consumer.Invoke(buffer, read);
            }
        }
    }
}
