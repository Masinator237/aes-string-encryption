using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
namespace StringEncryption
{
    class Handler
    {
        private static Random rnd; //random generator
        static Handler() //class constructor
        { 
            rnd = new Random(); //random generator needs to be initialized like this for it to not generate the same numbers ( different seed) 
        }
        private static byte[] encrypt_aes256(byte[] unencrypted, byte[] key, byte[] salt)
        {
            byte[] encrypted = null;
            using (MemoryStream memory_stream = new MemoryStream())
            {
                using (RijndaelManaged aes256 = new RijndaelManaged())
                {
                    aes256.KeySize = 256; //64 chars equals aes256 key size
                    aes256.BlockSize = 128;//block = algorithm(256)/2
                    Rfc2898DeriveBytes rfc_key = new Rfc2898DeriveBytes(key, salt, 2000);
                    aes256.Key = rfc_key.GetBytes(aes256.KeySize / 8);
                    aes256.IV = rfc_key.GetBytes(aes256.BlockSize / 8);
                    aes256.Mode = CipherMode.CBC;//encrypts into blocks
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, aes256.CreateEncryptor(), CryptoStreamMode.Write)) //creates the encryptor
                    {
                        crypto_stream.Write(unencrypted, 0, unencrypted.Length); //writes encrypted bytes to a memory stream
                        crypto_stream.Close();
                    }
                    encrypted = memory_stream.ToArray();
                }
            }
            return encrypted;
        }
        private static byte[] decrypt_aes256(byte[] encrypted, byte[] key, byte[] salt)
        {
           byte[] unencrypted = null;
            using (MemoryStream memory_stream = new MemoryStream())
            {
                using (RijndaelManaged aes256 = new RijndaelManaged())
                {
                    aes256.KeySize = 256; //64 chars equals aes256 key size
                    aes256.BlockSize = 128;//block = algorithm(256)/2
                    Rfc2898DeriveBytes rfc_key = new Rfc2898DeriveBytes(key, salt, 2000);
                    aes256.Key = rfc_key.GetBytes(aes256.KeySize / 8);
                    aes256.IV = rfc_key.GetBytes(aes256.BlockSize / 8);
                    aes256.Mode = CipherMode.CBC;//encrypts into blocks
                    using (CryptoStream crypto_stream = new CryptoStream(memory_stream, aes256.CreateDecryptor(), CryptoStreamMode.Write)) //creates the decryptor
                    {
                        crypto_stream.Write(encrypted, 0, encrypted.Length); //writes decrypted bytes to a memory stream
                        crypto_stream.Close();
                    }
                    unencrypted = memory_stream.ToArray();
                }
            }
            return unencrypted;
        }

        public static string encrypt(string unencrypted, string key, string salt)
        {
            byte[] unencrypted_bytes = Encoding.UTF8.GetBytes(unencrypted); //converts string to a byte array
            byte[] key_bytes = Encoding.UTF8.GetBytes(key); //converts key to a byte array
            key_bytes = SHA256Managed.Create().ComputeHash(key_bytes); //proceeds sha256 on the key array
            byte[] salt_bytes = Encoding.UTF8.GetBytes(salt); //converts salt to a byte array
            salt_bytes = SHA256Managed.Create().ComputeHash(salt_bytes); //proceeds sha256 on the salt array
            return Convert.ToBase64String(encrypt_aes256(unencrypted_bytes, key_bytes, salt_bytes)); //encrypts the array and converts to base64 (much better readibility and compatibility
        }

        public static string decrypt(string encrypted, string key, string salt)
        {
            byte[] encrypted_bytes = Convert.FromBase64String(encrypted); //converts the better readable base64 to raw byte array
            byte[] key_bytes = Encoding.UTF8.GetBytes(key); //converts key to a byte array
            key_bytes = SHA256Managed.Create().ComputeHash(key_bytes); //proceeds sha256 on the key array
            byte[] salt_bytes = Encoding.UTF8.GetBytes(salt); //converts salt to a byte array
            salt_bytes = SHA256Managed.Create().ComputeHash(salt_bytes); //proceeds sha256 on the salt array
            return Encoding.UTF8.GetString(decrypt_aes256(encrypted_bytes, key_bytes, salt_bytes)); //decrypts the array and converts it to a UTF8 string.
        }

        public static string random(int length)
        {
            string letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; //all chars we want to generate the random string from
            char[] random = new char[length + 1]; //char array where the random chars will be put in
            for (int i = 0; i <= length; i++) //loop to set the length
            {
                random[i] = letters[rnd.Next(letters.Length)]; //generates a random position and writes it to the array
            }
            return new string(random);
         
        }
    }
}
