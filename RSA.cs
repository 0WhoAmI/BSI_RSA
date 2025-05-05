using System.Numerics;
using System.Security.Cryptography;
using System.Text;

class RSA
{
    const int BlockSize = 10;
    const int BitLength = 768;

    static void Main()
    {
        string message = File.ReadAllText("message.txt", Encoding.ASCII);
        List<string> blocks = SplitToBlocks(message);
        List<BigInteger> numericBlocks = BlocksToNumbers(blocks);

        Console.WriteLine("Generowanie kluczy RSA...");
        BigInteger p = GenerateLargePrime(BitLength / 2);
        BigInteger q = GenerateLargePrime(BitLength / 2);
        BigInteger n = p * q;
        BigInteger phi = (p - 1) * (q - 1);
        BigInteger e = GenerateE(phi); // losowe e, gdzie: 1 < e < φ(n), NWD(e, φ(n)) = 1
        BigInteger d = ModInverse(e, phi); // d = e⁻¹ mod φ(n)

        Console.WriteLine($"Publiczny klucz (e, n): ({e}, {n})");
        Console.WriteLine($"Prywatny klucz (d, n): ({d}, {n})");

        List<BigInteger> encrypted = new();
        foreach (BigInteger block in numericBlocks)
            encrypted.Add(BigInteger.ModPow(block, e, n));

        List<BigInteger> decrypted = new();
        foreach (BigInteger encryptedBlock in encrypted)
            decrypted.Add(BigInteger.ModPow(encryptedBlock, d, n));

        List<string> decryptedText = NumbersToBlocks(decrypted);
        string finalMessage = string.Join("", decryptedText);

        Console.WriteLine("\nWiadomość odszyfrowana:");
        Console.WriteLine(finalMessage);

        Console.WriteLine("\nSprawdzenie:");
        Console.WriteLine(finalMessage == message ? "OK – wiadomość się zgadza." : "BŁĄD – wiadomość się nie zgadza.");
    }

    static List<string> SplitToBlocks(string input)
    {
        List<string> blocks = new();
        for (int i = 0; i < input.Length; i += BlockSize)
        {
            string block = input.Substring(i, Math.Min(BlockSize, input.Length - i));
            if (block.Length < BlockSize)
                block = block.PadRight(BlockSize, ' ');
            blocks.Add(block);
        }
        return blocks;
    }

    static List<BigInteger> BlocksToNumbers(List<string> blocks)
    {
        List<BigInteger> numbers = new();
        foreach (string block in blocks)
        {
            byte[] bytes = Encoding.ASCII.GetBytes(block);
            Array.Reverse(bytes);
            numbers.Add(new BigInteger(bytes));
        }
        return numbers;
    }

    static List<string> NumbersToBlocks(List<BigInteger> numbers)
    {
        List<string> blocks = new();
        foreach (BigInteger num in numbers)
        {
            byte[] bytes = num.ToByteArray();
            Array.Resize(ref bytes, BlockSize);
            Array.Reverse(bytes);
            blocks.Add(Encoding.ASCII.GetString(bytes).TrimEnd(' '));
        }
        return blocks;
    }

    static BigInteger GenerateLargePrime(int bits)
    {
        using var rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[bits / 8];
        BigInteger p;
        do
        {
            rng.GetBytes(bytes);
            bytes[^1] |= 0x80; // wymuszenie długości
            bytes[0] |= 1;     // nieparzysta liczba
            p = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        } while (!IsProbablePrime(p, 20));
        return p;
    }

    // Test Millera-Rabina
    static bool IsProbablePrime(BigInteger n, int rounds)
    {
        if (n < 2) return false;
        if (n == 2 || n == 3) return true;
        if (n % 2 == 0) return false;

        BigInteger d = n - 1;
        int s = 0;
        while (d % 2 == 0)
        {
            d /= 2;
            s++;
        }

        using var rng = RandomNumberGenerator.Create();
        byte[] bytes = new byte[n.GetByteCount()];

        for (int i = 0; i < rounds; i++)
        {
            BigInteger a;
            do
            {
                rng.GetBytes(bytes);
                a = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            } while (a < 2 || a >= n - 2);

            BigInteger x = BigInteger.ModPow(a, d, n);
            if (x == 1 || x == n - 1) continue;

            bool passed = false;
            for (int r = 0; r < s - 1; r++)
            {
                x = BigInteger.ModPow(x, 2, n);
                if (x == n - 1)
                {
                    passed = true;
                    break;
                }
            }
            if (!passed) return false;
        }
        return true;
    }

    static BigInteger GenerateE(BigInteger phi)
    {
        BigInteger e;
        var rng = RandomNumberGenerator.Create();
        do
        {
            byte[] bytes = new byte[phi.GetByteCount()];
            rng.GetBytes(bytes);
            bytes[^1] |= 0x80; // pełna długość
            bytes[0] |= 1;     // nieparzysta

            e = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }
        while (e <= 1 || e >= phi || BigInteger.GreatestCommonDivisor(e, phi) != 1);

        return e;
    }

    static BigInteger ModInverse(BigInteger a, BigInteger m)
    {
        BigInteger m0 = m, t, q;
        BigInteger x0 = 0, x1 = 1;

        if (m == 1) return 0;

        while (a > 1)
        {
            q = a / m;
            t = m;
            m = a % m; a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }

        return x1 < 0 ? x1 + m0 : x1;
    }
}