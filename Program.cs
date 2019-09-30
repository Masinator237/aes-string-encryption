using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
namespace StringEncryption
{

    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("String Encryption sample");
            string unencrypted = "string_encryption";
            Console.WriteLine("Unencrypted string: " + unencrypted);
            string salt = Handler.random(64); //random salt
            Console.WriteLine("Salt: " + salt);
            string key = Handler.random(64); //random key
            Console.WriteLine("Key: " + key);
            string encrypted = Handler.encrypt(unencrypted, key, salt); //encrypted the plain string
            Console.WriteLine("Encrypted: " + encrypted);
            string decrypted = Handler.decrypt(encrypted, key, salt); //decrypt the encrypted string
            Console.WriteLine("Decrypted: " + decrypted);
            Console.ReadLine();
        }
    }
}
