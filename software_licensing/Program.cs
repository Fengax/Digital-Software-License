using FluentFTP;
using System;
using System.Collections.Generic;
using System.IO;
using System.Collections;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Security.Cryptography;

namespace software_licensing
{
    class Program
    {
        //Generate token
        internal static readonly char[] chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
        static string GetUniqueKeyOriginal_BIASED(int size)
        {
            char[] chars =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
            byte[] data = new byte[size];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }
            StringBuilder result = new StringBuilder(size);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        internal static readonly string token = GetUniqueKeyOriginal_BIASED(10);

        //Encryption
        static string encrypt(string encryptString)
        {
            string EncryptionKey = token;
            byte[] clearBytes = Encoding.Unicode.GetBytes(encryptString);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
            0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
        });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    encryptString = Convert.ToBase64String(ms.ToArray());
                }
            }
            return encryptString;
        }

        //Decrypt
        static string Decrypt(string cipherText)
        {
            string EncryptionKey = token;
            cipherText = cipherText.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(cipherText);
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] {
            0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76
        });
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    cipherText = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return cipherText;
        }
        //Connect to server animation function
        public static void connectToServerAnimation()
        {
            Console.Write("Connecting to server... ");
            string[] chars = {"/", "|", @"\", "-"};
            while (true)
            {
                foreach (string chare in chars)
                {
                    Console.Write(chare);
                    Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                    Thread.Sleep(100);
                }
            }
        }

        //Checking license animation
        public static void checkingLicenseAnimation()
        {
            Console.Write("Checking license... ");
            string[] chars = { "/", "|", @"\", "-" };
            while (true)
            {
                foreach (string chare in chars)
                {
                    Console.Write(chare);
                    Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                    Thread.Sleep(100);
                }
            }
        }

        //Clear current line function
        public static void ClearCurrentConsoleLine()
        {
            int currentLineCursor = Console.CursorTop;
            Console.SetCursorPosition(0, Console.CursorTop);
            Console.Write(new string(' ', Console.WindowWidth));
            Console.SetCursorPosition(0, currentLineCursor);
        }

        //Console print function for callback

        static void ConsolePrint(FtpProgress i)
        {
            Console.WriteLine(i.Progress.ToString());
        }

        //Decode function for memory stream to string
        static string decode(MemoryStream mem)
        {
            string result = Encoding.Default.GetString(mem.ToArray());
            return result;
        }
        
        //Encode functino for string to memory stream
        static MemoryStream encode(string content)
        {
            byte[] byteArray = Encoding.UTF8.GetBytes(content);
            //byte[] byteArray = Encoding.ASCII.GetBytes(contents);
            MemoryStream stream = new MemoryStream(byteArray);
            return stream;
        }

        //Get mac address
        static List<string> GetMacAddress()
        {
            List<string> macList = new List<string>();
            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface intrface in nics)
            {
                PhysicalAddress address = intrface.GetPhysicalAddress();
                byte[] bytes = address.GetAddressBytes();
                string address_string = "";
                for (int i = 0; i < bytes.Length; i++)
                {
                    // Display the physical address in hexadecimal.
                    address_string = address_string + bytes[i].ToString("X2");
                    // Insert a hyphen after each byte, unless we are at the end of the
                    // address.
                    if (i != bytes.Length - 1)
                    {
                        address_string = address_string + "-";
                    }
                }
                macList.Add(address_string);
            }
            return macList;
        }

        //Remove random characters from string
        static string RemoveWhitespace(string input)
        {
            string output = "";
            foreach(char c in input)
            {
                if (Char.IsLetterOrDigit(c))
                {
                    output = output + c;
                }
            }
            return output;
        }

        //Get Disk Serial
        static List<string> GetDiskSerial()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PhysicalMedia");
            List<string> diskSerialList = new List<string>();
            string diskSerial = "";

            foreach (ManagementObject wmi_HD in searcher.Get())
            {
                // get the hardware serial no.
                if (wmi_HD["SerialNumber"] != null)
                {
                    diskSerial = wmi_HD["SerialNumber"].ToString();
                    diskSerialList.Add(RemoveWhitespace(diskSerial));
                }
            }

            return diskSerialList;
        }

        internal static readonly string usernameEncrypt = encrypt("epiz_26743690");
        internal static readonly string passwordEncrypt = encrypt("4a6aJvDNudgPhlg");
        internal static readonly string serverAddr = "ftpupload.net";

        //Main
        static void Main(string[] args)
        {
            bool valid = false;

            //Create child thread for animation
            Thread childThread = new Thread(connectToServerAnimation);
            childThread.Start();

            //Connect to FTP Client
            FtpClient client = new FtpClient(serverAddr);
            client.Credentials = new NetworkCredential(Decrypt(usernameEncrypt), Decrypt(passwordEncrypt));
            client.Connect();

            //Ending child thread for animation
            childThread.Abort();
            ClearCurrentConsoleLine();

            string key = "";
            

            //Check if key file exists
            if (File.Exists("key.txt"))
            {
                key = File.ReadAllText("key.txt");
            }
            else
            {
                //Get key
                Console.Write("Enter your key: ");
                key = Console.ReadLine();
                StreamWriter sw = File.CreateText("key.txt");
                sw.Close();
                File.WriteAllText("key.txt", key);
                Console.SetCursorPosition(0, Console.CursorTop - 1);
                ClearCurrentConsoleLine();
            }

            string license_dir = @"/htdocs/" + key + ".txt";

            //Check if license is valid
            if (client.FileExists(license_dir))
            {
                //Creating child thread for checking license animation
                Thread childThread2 = new Thread(checkingLicenseAnimation);
                childThread2.Start();
                //Memory stream and callback
                MemoryStream mem = new MemoryStream();
                Action<FtpProgress> progress = null;

                //Read license file to memory
                client.Download(mem, license_dir, 0, progress);

                //Splitting license information into array
                string[] licenseInformation = decode(mem).Split(new[] { Environment.NewLine }, StringSplitOptions.None);

                //Get device mac address and disk serial
                List<string> macList = new List<string>();
                macList = GetMacAddress();
                List<string> diskSerialList = new List<string>();
                diskSerialList = GetDiskSerial();

                //Check if is registered
                if (licenseInformation[0] == "registered")
                {
                    //Check mac address and disk serial
                    if (macList.Contains(licenseInformation[1]) && diskSerialList.Contains(licenseInformation[2]))
                    {
                        valid = true;
                    }
                    else
                    {
                        valid = false;
                    }
                }
                else
                {
                    //Upload device ID to license info
                    string licenseInfoString = "";
                    licenseInformation[0] = "registered";
                    foreach (string info in licenseInformation)
                    {
                        licenseInfoString = licenseInfoString + info + Environment.NewLine;
                    }
                    client.Upload(encode(licenseInfoString), license_dir, FtpRemoteExists.Overwrite);
                    valid = true;
                }

                //Ending child thread once task is finished
                childThread2.Abort();
                ClearCurrentConsoleLine();

                if (valid)
                {
                    Console.WriteLine("License successfully verified");
                    Console.ReadLine();
                }
                else
                {
                    Console.WriteLine("Invalid license");
                    Console.ReadLine();
                }
            }
            else
            {
                Console.WriteLine("Invalid license");
                Console.ReadLine();
            }

            
        }
    }
}
