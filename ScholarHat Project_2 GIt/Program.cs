using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        while (true)
        {
            Console.Clear(); // Clear the console for a clean UI
            DrawHeader();

            Console.WriteLine("Choose an encryption method or exit:");
            Console.WriteLine("1. Caesar Cipher");
            Console.WriteLine("2. AES Encryption");
            Console.WriteLine("3. Exit");

            string choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    Console.Clear();
                    DrawHeader("Caesar Cipher");
                    HandleCaesarCipher();
                    break;

                case "2":
                    Console.Clear();
                    DrawHeader("AES Encryption");
                    HandleAesEncryption();
                    break;

                case "3":
                    Console.WriteLine("\nThank you for using the encryption program!");
                    return;

                default:
                    DisplayError("Invalid option, please choose a valid method (1, 2, or 3).");
                    break;
            }

            // Wait for the user to press Enter before returning to the menu
            Console.WriteLine("\nPress Enter to return to the main menu...");
            Console.ReadLine();
        }
    }

    // Draw a clean header with a title for sections
    static void DrawHeader(string subtitle = "")
    {
        Console.WriteLine("============================================");
        Console.WriteLine("          ENCRYPTION AND DECRYPTION         ");
        Console.WriteLine("============================================");

        if (!string.IsNullOrEmpty(subtitle))
        {
            Console.WriteLine(">> " + subtitle);
            Console.WriteLine("============================================\n");
        }
    }

    static void HandleCaesarCipher()
    {
        Console.Write("Enter the string to encrypt: ");
        string input = Console.ReadLine();
        int shift = GetShiftInput();

        char[] characters = input.ToCharArray();
        char[] encodedChars = CaesarEncode(characters, shift);
        string encodedResult = new string(encodedChars);

        char[] decodedChars = CaesarDecode(encodedChars, shift);
        string decodedResult = new string(decodedChars);

        Console.WriteLine($"\n[Caesar Cipher] Encrypted string: {encodedResult}");
        Console.WriteLine($"[Caesar Cipher] Decrypted string: {decodedResult}");
    }

    static void HandleAesEncryption()
    {
        using (Aes aes = Aes.Create())
        {
            Console.Write("Enter the string to encrypt: ");
            string input = Console.ReadLine();

            aes.GenerateKey();
            aes.GenerateIV();

            byte[] key = aes.Key;
            byte[] iv = aes.IV;

            Console.WriteLine($"\nOriginal string: {input}");

            byte[] encryptedBytes = EncryptStringToBytes_Aes(input, key, iv);
            string encryptedString = Convert.ToBase64String(encryptedBytes);
            Console.WriteLine("[AES] Encrypted string: " + encryptedString);

            byte[] encryptedBytesFromBase64 = Convert.FromBase64String(encryptedString);
            string decryptedString = DecryptStringFromBytes_Aes(encryptedBytesFromBase64, key, iv);
            Console.WriteLine("[AES] Decrypted string: " + decryptedString);
        }
    }

    // Get a valid shift value for Caesar Cipher
    static int GetShiftInput()
    {
        int shift;
        while (true)
        {
            Console.Write("Enter the shift value (e.g., 2): ");
            if (int.TryParse(Console.ReadLine(), out shift))
            {
                return shift;
            }
            else
            {
                DisplayError("Invalid input. Please enter a valid integer.");
            }
        }
    }

    static void DisplayError(string message)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("\nError: " + message);
        Console.ResetColor();
    }

    // Caesar Cipher encoding
    static char[] CaesarEncode(char[] characters, int shift)
    {
        for (int i = 0; i < characters.Length; i++)
        {
            char c = characters[i];

            if (char.IsLetter(c))
            {
                char offset = char.IsUpper(c) ? 'A' : 'a';
                c = (char)(((c + shift - offset) % 26) + offset);
            }

            characters[i] = c;
        }
        return characters;
    }

    // Caesar Cipher decoding
    static char[] CaesarDecode(char[] characters, int shift)
    {
        for (int i = 0; i < characters.Length; i++)
        {
            char c = characters[i];

            if (char.IsLetter(c))
            {
                char offset = char.IsUpper(c) ? 'A' : 'a';
                c = (char)(((c - shift - offset + 26) % 26) + offset);
            }

            characters[i] = c;
        }
        return characters;
    }

    // AES encryption method
    static byte[] EncryptStringToBytes_Aes(string plainText, byte[] key, byte[] iv)
    {
        if (plainText == null || plainText.Length <= 0)
            throw new ArgumentNullException("plainText");
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException("key");
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException("iv");

        byte[] encrypted;

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                    encrypted = ms.ToArray();
                }
            }
        }

        return encrypted;
    }

    // AES decryption method
    static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] key, byte[] iv)
    {
        if (cipherText == null || cipherText.Length <= 0)
            throw new ArgumentNullException("cipherText");
        if (key == null || key.Length <= 0)
            throw new ArgumentNullException("key");
        if (iv == null || iv.Length <= 0)
            throw new ArgumentNullException("iv");

        string plainText = null;

        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;

            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        plainText = sr.ReadToEnd();
                    }
                }
            }
        }

        return plainText;
    }
}
