using System.Collections;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;



namespace SecureChat
{

    public class EncryptionTechniques
    {

        // Caesar Cipher
        public static string CaesarCipherEncrypt(string plaintext, string key)
        {
            int shift = Convert.ToInt32(key);
            StringBuilder result = new StringBuilder();

            foreach (char ch in plaintext)
            {
                if (char.IsLetter(ch))
                {
                    char baseChar = char.IsUpper(ch) ? 'A' : 'a';
                    result.Append((char)((((ch + shift) - baseChar) % 26) + baseChar));
                }
                else
                {
                    result.Append(ch);
                }
            }

            return result.ToString();
        }

        public static string CaesarCipherDecrypt(string ciphertext, string key)
        {
            int shift = Convert.ToInt32(key);
            return CaesarCipherEncrypt(ciphertext, (26 - shift).ToString());
        }

        // Monoalphabetic Substitution Cipher
        public static string MonoalphabeticEncrypt(string plaintext, string key)
        {
            // Assume key is a 26-character permutation of the alphabet
            if (key.Length != 26) throw new ArgumentException("Key must be 26 characters long");

            Dictionary<char, char> substitutionMap = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                substitutionMap[(char)('A' + i)] = char.ToUpper(key[i]);
                substitutionMap[(char)('a' + i)] = char.ToLower(key[i]);
            }

            StringBuilder result = new StringBuilder();
            foreach (char ch in plaintext)
            {
                result.Append(substitutionMap.ContainsKey(ch) ? substitutionMap[ch] : ch);
            }

            return result.ToString();
        }

        public static string MonoalphabeticDecrypt(string ciphertext, string key)
        {
            // Reverse the substitution map
            if (key.Length != 26) throw new ArgumentException("Key must be 26 characters long");

            Dictionary<char, char> reverseMap = new Dictionary<char, char>();
            for (int i = 0; i < 26; i++)
            {
                reverseMap[char.ToUpper(key[i])] = (char)('A' + i);
                reverseMap[char.ToLower(key[i])] = (char)('a' + i);
            }

            StringBuilder result = new StringBuilder();
            foreach (char ch in ciphertext)
            {
                result.Append(reverseMap.ContainsKey(ch) ? reverseMap[ch] : ch);
            }

            return result.ToString();
        }

        public static string PolyalphabeticEncrypt(string plaintext, string key)
        {
            if (string.IsNullOrEmpty(key) || !key.All(char.IsLetter))
                throw new ArgumentException("Key must be non-empty and contain only alphabetic characters.");

            StringBuilder result = new StringBuilder();
            key = key.ToUpper(); // Ensure key is uppercase for consistent shift calculation
            int keyLength = key.Length;

            for (int i = 0, j = 0; i < plaintext.Length; i++)
            {
                char ch = plaintext[i];

                if (char.IsLetter(ch))
                {
                    char baseChar = char.IsUpper(ch) ? 'A' : 'a';
                    int shift = key[j % keyLength] - 'A'; // Calculate shift based on key character
                    result.Append((char)((((ch - baseChar + shift) % 26) + baseChar)));
                    j++; // Move to the next key character only for alphabetic input
                }
                else
                {
                    result.Append(ch); // Preserve non-alphabetic characters
                }
            }

            return result.ToString();
        }

        public static string PolyalphabeticDecrypt(string ciphertext, string key)
        {
            if (string.IsNullOrEmpty(key) || !key.All(char.IsLetter))
                throw new ArgumentException("Key must be non-empty and contain only alphabetic characters.");

            StringBuilder result = new StringBuilder();
            key = key.ToUpper(); // Ensure key is uppercase for consistent shift calculation
            int keyLength = key.Length;

            for (int i = 0, j = 0; i < ciphertext.Length; i++)
            {
                char ch = ciphertext[i];

                if (char.IsLetter(ch))
                {
                    char baseChar = char.IsUpper(ch) ? 'A' : 'a';
                    int shift = key[j % keyLength] - 'A'; // Calculate shift based on key character
                    result.Append((char)((((ch - baseChar - shift + 26) % 26) + baseChar)));
                    j++; // Move to the next key character only for alphabetic input
                }
                else
                {
                    result.Append(ch); // Preserve non-alphabetic characters
                }
            }

            return result.ToString();
        }


        // Hill Cipher Technique
        public static class HillCipher
        {
            // Encrypt plaintext using an n×n key matrix (provided as a string)
            public static string Encrypt(string plaintext, string key)
            {
                key = key.ToUpper();
                int n = (int)Math.Sqrt(key.Length);
                if (n * n != key.Length)
                    throw new ArgumentException("Key length must be a perfect square.");

                plaintext = plaintext.ToUpper().Replace(" ", "");
                while (plaintext.Length % n != 0)
                    plaintext += 'X'; // Pad with 'X'

                int[,] keyMatrix = ConstructKeyMatrix(key);
                StringBuilder result = new StringBuilder();

                for (int i = 0; i < plaintext.Length; i += n)
                {
                    int[] vector = new int[n];
                    for (int j = 0; j < n; j++)
                        vector[j] = plaintext[i + j] - 'A';

                    // Encrypt block
                    for (int row = 0; row < n; row++)
                    {
                        int sum = 0;
                        for (int col = 0; col < n; col++)
                            sum += keyMatrix[row, col] * vector[col];

                        sum = (sum % 26 + 26) % 26; // Ensure positive
                        result.Append((char)(sum + 'A'));
                    }
                }
                return result.ToString();
            }

            // Decrypt ciphertext using the inverse key matrix
            public static string Decrypt(string ciphertext, string key)
            {
                key = key.ToUpper(); // Force uppercase
                int n = (int)Math.Sqrt(key.Length);
                if (n * n != key.Length)
                    throw new ArgumentException("Key length must be a perfect square.");

                ciphertext = ciphertext.ToUpper().Replace(" ", "");
                if (ciphertext.Length % n != 0)
                    throw new ArgumentException("Ciphertext length is not a multiple of the key size.");

                int[,] keyMatrix = ConstructKeyMatrix(key);
                int[,] inverseMatrix = CalculateInverseMatrix(keyMatrix);
                StringBuilder result = new StringBuilder();

                for (int i = 0; i < ciphertext.Length; i += n)
                {
                    int[] vector = new int[n];
                    for (int j = 0; j < n; j++)
                        vector[j] = ciphertext[i + j] - 'A';

                    // Decrypt block
                    for (int row = 0; row < n; row++)
                    {
                        int sum = 0;
                        for (int col = 0; col < n; col++)
                            sum += inverseMatrix[row, col] * vector[col];

                        sum = (sum % 26 + 26) % 26;
                        result.Append((char)(sum + 'A'));
                    }
                }

                string decrypted = result.ToString();
                // Remove padding 'X' if present
                int lastX = decrypted.LastIndexOf('X');
                if (lastX >= 0 && lastX == decrypted.Length - 1)
                    decrypted = decrypted.Substring(0, lastX);

                return decrypted;

            }

            // Build the key matrix in row-major order
            private static int[,] ConstructKeyMatrix(string key)
            {
                key = key.ToUpper(); // Ensure uppercase
                int n = (int)Math.Sqrt(key.Length);
                int[,] keyMatrix = new int[n, n];
                for (int i = 0; i < key.Length; i++)
                {
                    keyMatrix[i / n, i % n] = key[i] - 'A'; // Now safe for uppercase
                }


                int det = DeterminantMod(keyMatrix, 26);
                det = (det % 26 + 26) % 26;
                if (HillGCD(det, 26) != 1)
                    throw new ArgumentException("Key matrix is not invertible modulo 26.");

                return keyMatrix;
            }

            // Calculate the inverse matrix modulo 26
            private static int[,] CalculateInverseMatrix(int[,] matrix)
            {
                int mod = 26;
                int det = DeterminantMod(matrix, mod);
                det = (det % mod + mod) % mod;
                int detInv = ModInverse(det, mod);
                int[,] adj = AdjugateMatrix(matrix, mod);
                int n = matrix.GetLength(0);
                int[,] inv = new int[n, n];

                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        inv[i, j] = (adj[i, j] * detInv) % mod;
                        if (inv[i, j] < 0) inv[i, j] += mod; // Ensure positivity
                    }
                }
                return inv;
            }

            // Compute the adjugate matrix (transpose of cofactors)
            private static int[,] AdjugateMatrix(int[,] matrix, int mod)
            {
                int n = matrix.GetLength(0);
                int[,] adj = new int[n, n];
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        int[,] minor = GetSubMatrix(matrix, i, j);
                        int cofactor = ((i + j) % 2 == 0 ? 1 : -1) * DeterminantMod(minor, mod);
                        adj[j, i] = (cofactor % mod + mod) % mod; // Transpose here
                    }
                }
                return adj;
            }

            // Recursive determinant calculation
            private static int DeterminantMod(int[,] matrix, int mod)
            {
                int n = matrix.GetLength(0);
                if (n == 1) return matrix[0, 0] % mod;
                if (n == 2)
                    return (matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0]) % mod;

                int det = 0;
                for (int col = 0; col < n; col++)
                {
                    int[,] minor = GetSubMatrix(matrix, 0, col);
                    int sign = col % 2 == 0 ? 1 : -1;
                    det += sign * matrix[0, col] * DeterminantMod(minor, mod);
                }
                return (det % mod + mod) % mod;
            }

            // Helper: Get submatrix excluding row and column
            private static int[,] GetSubMatrix(int[,] matrix, int excludeRow, int excludeCol)
            {
                int n = matrix.GetLength(0);
                int[,] sub = new int[n - 1, n - 1];
                for (int i = 0, r = 0; i < n; i++)
                {
                    if (i == excludeRow) continue;
                    for (int j = 0, c = 0; j < n; j++)
                    {
                        if (j == excludeCol) continue;
                        sub[r, c++] = matrix[i, j];
                    }
                    r++;
                }
                return sub;
            }

            // GCD and Modular Inverse
            private static int HillGCD(int a, int b) => b == 0 ? a : HillGCD(b, a % b);
            private static int ModInverse(int a, int mod)
            {
                a = (a % mod + mod) % mod;
                for (int x = 1; x < mod; x++)
                    if ((a * x) % mod == 1) return x;
                throw new ArgumentException("No modular inverse exists.");
            }
        }


        // Playfair Technique
        public static string PlayfairEncrypt(string plaintext, string key)
        {
            key = key.ToUpper().Replace("J", "I");
            plaintext = plaintext.ToUpper().Replace("J", "I").Replace(" ", "");

            char[,] matrix = CreatePlayfairMatrix(key);
            plaintext = PreparePlaintextPairs(plaintext);

            StringBuilder result = new StringBuilder();

            for (int i = 0; i < plaintext.Length; i += 2)
            {
                char a = plaintext[i];
                char b = plaintext[i + 1];

                int[] posA = FindPosition(matrix, a);
                int[] posB = FindPosition(matrix, b);

                if (posA[0] == posB[0])
                {
                    result.Append(matrix[posA[0], (posA[1] + 1) % 5]);
                    result.Append(matrix[posB[0], (posB[1] + 1) % 5]);
                }
                else if (posA[1] == posB[1])
                {
                    result.Append(matrix[(posA[0] + 1) % 5, posA[1]]);
                    result.Append(matrix[(posB[0] + 1) % 5, posB[1]]);
                }
                else
                {
                    result.Append(matrix[posA[0], posB[1]]);
                    result.Append(matrix[posB[0], posA[1]]);
                }
            }

            return result.ToString();
        }

        public static string PlayfairDecrypt(string ciphertext, string key)
        {
            key = key.ToUpper().Replace("J", "I");
            ciphertext = ciphertext.ToUpper().Replace("J", "I").Replace(" ", "");

            char[,] matrix = CreatePlayfairMatrix(key);

            StringBuilder result = new StringBuilder();

            for (int i = 0; i < ciphertext.Length; i += 2)
            {
                char a = ciphertext[i];
                char b = ciphertext[i + 1];

                int[] posA = FindPosition(matrix, a);
                int[] posB = FindPosition(matrix, b);

                if (posA[0] == posB[0])
                {
                    result.Append(matrix[posA[0], (posA[1] - 1 + 5) % 5]);
                    result.Append(matrix[posB[0], (posB[1] - 1 + 5) % 5]);
                }
                else if (posA[1] == posB[1])
                {
                    result.Append(matrix[(posA[0] - 1 + 5) % 5, posA[1]]);
                    result.Append(matrix[(posB[0] - 1 + 5) % 5, posB[1]]);
                }
                else
                {
                    result.Append(matrix[posA[0], posB[1]]);
                    result.Append(matrix[posB[0], posA[1]]);
                }
            }

            return RemoveExtraX(result.ToString());
        }

        private static string RemoveExtraX(string text)
        {
            StringBuilder cleanedText = new StringBuilder();
            for (int i = 0; i < text.Length; i++)
            {
                if (i > 0 && text[i] == 'X' && (i == text.Length - 1 || text[i - 1] == text[i + 1]))
                    continue;
                cleanedText.Append(text[i]);
            }
            return cleanedText.ToString();
        }


        // OTP
        public static string GenerateRandomKey(int length)
        {
            Random random = new Random();
            char[] key = new char[length];
            for (int i = 0; i < length; i++)
            {
                // Random uppercase letter (ASCII 65 to 90 inclusive)
                key[i] = (char)random.Next(65, 91);
            }
            return new string(key);
        }

        // Combines the plaintext with the one-time pad key using XOR to produce the ciphertext
        public static string OTPEncrypt(string plaintext, string key)
        {
            if (plaintext.Length != key.Length)
                throw new ArgumentException("Key length must match plaintext length.");

            char[] ciphertext = new char[plaintext.Length];

            for (int i = 0; i < plaintext.Length; i++)
            {
                // XOR each character from plaintext and key
                int p = plaintext[i]; // ASCII value of plaintext character
                int k = key[i];       // ASCII value of key character
                int c = p ^ k;        // XOR operation
                ciphertext[i] = (char)c;
            }

            return new string(ciphertext);
        }

        // Recovers the original plaintext by XORing the ciphertext with the one-time pad key
        public static string OTPDecrypt(string ciphertext, string key)
        {
            if (ciphertext.Length != key.Length)
                throw new ArgumentException("Key length must match ciphertext length.");

            char[] plaintext = new char[ciphertext.Length];

            for (int i = 0; i < ciphertext.Length; i++)
            {
                int c = ciphertext[i]; // ASCII value of ciphertext character
                int k = key[i];        // ASCII value of key character
                int p = c ^ k;         // XOR operation reverses the encryption
                plaintext[i] = (char)p;
            }

            return new string(plaintext);
        }

        // Securely destroys the key by overwriting its contents and nulling its reference.
        // In a real-world scenario, you might need additional secure memory handling.
        public static void DestroyKey(ref string? key)
        {
            if (key != null)
            {
                // Overwrite key characters with zeros
                char[] keyChars = key.ToCharArray();
                for (int i = 0; i < keyChars.Length; i++)
                    keyChars[i] = '\0';

                // Null out the reference to prevent reuse.
                key = null;
            }
        }


        //Rail Fence 
        public static string RailFenceEncrypt(string plaintext, string key)
        {
            // Convert key string to integer (number of rails)
            if (!int.TryParse(key, out int railKey))
            {
                throw new ArgumentException("Key must be an integer.");
            }

            // Create a 2D array to store the rails
            char[,] fence = new char[railKey, plaintext.Length];
            int row = 0;
            bool down = false;

            // Fill the fence (zigzag pattern), treat spaces as valid characters
            for (int i = 0; i < plaintext.Length; i++)
            {
                fence[row, i] = plaintext[i];

                // Change direction at the top and bottom rows
                if (row == 0 || row == railKey - 1)
                    down = !down;

                row += down ? 1 : -1;
            }

            // Read the fence row by row to form the ciphertext
            StringBuilder result = new StringBuilder();
            for (int r = 0; r < railKey; r++)
            {
                for (int c = 0; c < plaintext.Length; c++)
                {
                    if (fence[r, c] != '\0')  // Check for non-empty cells
                        result.Append(fence[r, c]);
                }
            }

            return result.ToString();
        }

        // Rail Fence Decryption with spaces
        public static string RailFenceDecrypt(string ciphertext, string key)
        {
            // Convert key string to integer (number of rails)
            if (!int.TryParse(key, out int railKey))
            {
                throw new ArgumentException("Key must be an integer.");
            }

            // Create a 2D array for the fence
            char[,] fence = new char[railKey, ciphertext.Length];
            int[] railPositions = new int[ciphertext.Length];
            int row = 0;
            bool down = false;

            // Determine where each letter will be placed in the fence
            for (int i = 0; i < ciphertext.Length; i++)
            {
                railPositions[i] = row;
                if (row == 0 || row == railKey - 1)
                    down = !down;

                row += down ? 1 : -1;
            }

            // Fill the fence with characters from the ciphertext
            int index = 0;
            for (int r = 0; r < railKey; r++)
            {
                for (int i = 0; i < ciphertext.Length; i++)
                {
                    if (railPositions[i] == r)
                        fence[r, i] = ciphertext[index++];
                }
            }

            // Read the fence column by column to get the decrypted plaintext
            StringBuilder result = new StringBuilder();
            for (int i = 0; i < ciphertext.Length; i++)
            {
                result.Append(fence[railPositions[i], i]);
            }

            return result.ToString();
        }


        // Columnar Transposition Cipher
        public static string ColumnarEncrypt(string plaintext, string key)
        {
            key = key.ToUpper();
            int[] order = GetKeyOrder(key);
            int columns = key.Length;

            int rows = (int)Math.Ceiling((double)plaintext.Length / columns);
            char[,] grid = new char[rows, columns];

            // Fill grid
            int k = 0;
            for (int r = 0; r < rows; r++)
            {
                for (int c = 0; c < columns; c++)
                {
                    if (k < plaintext.Length)
                        grid[r, c] = plaintext[k++];
                    else
                        grid[r, c] = 'X'; // Padding
                }
            }

            // Read by column order
            StringBuilder result = new StringBuilder();
            for (int c = 0; c < columns; c++)
            {
                int actualColumn = Array.IndexOf(order, c);
                for (int r = 0; r < rows; r++)
                {
                    result.Append(grid[r, actualColumn]);
                }
            }

            return result.ToString(); // Ensure return statement
        }


        // Helper Methods
        public static char[,] CreatePlayfairMatrix(string key)
        {
            char[,] matrix = new char[5, 5];
            bool[] used = new bool[26];
            int row = 0, col = 0;

            foreach (char ch in key)
            {
                if (!used[ch - 'A'])
                {
                    matrix[row, col] = ch;
                    used[ch - 'A'] = true;
                    col++;
                    if (col == 5) { row++; col = 0; }
                }
            }

            for (char ch = 'A'; ch <= 'Z'; ch++)
            {
                if (ch == 'J') continue;
                if (!used[ch - 'A'])
                {
                    matrix[row, col] = ch;
                    used[ch - 'A'] = true;
                    col++;
                    if (col == 5) { row++; col = 0; }
                }
            }

            return matrix;
        }

        public static int[] FindPosition(char[,] matrix, char ch)
        {
            for (int r = 0; r < 5; r++)
            {
                for (int c = 0; c < 5; c++)
                {
                    if (matrix[r, c] == ch)
                        return new int[] { r, c };
                }
            }
            throw new ArgumentException($"Character {ch} not found in matrix");
        }

        public static string PreparePlaintextPairs(string plaintext)
        {
            StringBuilder prepared = new StringBuilder();
            for (int i = 0; i < plaintext.Length; i++)
            {
                if (i + 1 < plaintext.Length && plaintext[i] == plaintext[i + 1])
                {
                    prepared.Append(plaintext[i]);
                    prepared.Append('X');
                }
                else
                {
                    prepared.Append(plaintext[i]);
                }
            }

            if (prepared.Length % 2 != 0)
                prepared.Append('X');

            return prepared.ToString();
        }

        public static int ModularMultiplicativeInverse(int a, int m)
        {
            a = a % m;
            for (int x = 1; x < m; x++)
            {
                if ((a * x) % m == 1)
                    return x;
            }
            return 1;
        }

        public static int[] GetKeyOrder(string key)
        {
            int[] order = new int[key.Length];
            List<char> sortedKey = key.ToCharArray().ToList();
            sortedKey.Sort();

            for (int i = 0; i < key.Length; i++)
            {
                order[i] = sortedKey.IndexOf(key[i]);
                sortedKey[order[i]] = (char)('Z' + 1);
            }

            return order;
        }


        // Ensure Columnar encryption returns a value by adding a default return
        public static string ColumnarDecrypt(string ciphertext, string key)
        {
            key = key.ToUpper();
            int[] order = GetKeyOrder(key);
            int columns = key.Length;

            int rows = (int)Math.Ceiling((double)ciphertext.Length / columns);
            char[,] grid = new char[rows, columns];

            // Fill grid by column order
            int k = 0;
            for (int c = 0; c < columns; c++)
            {
                int actualColumn = Array.IndexOf(order, c);
                for (int r = 0; r < rows; r++)
                {
                    if (k < ciphertext.Length)
                        grid[r, actualColumn] = ciphertext[k++];
                }
            }

            // Read row by row
            StringBuilder result = new StringBuilder();
            for (int r = 0; r < rows; r++)
            {
                for (int c = 0; c < columns; c++)
                {
                    if (grid[r, c] != 0)
                        result.Append(grid[r, c]);
                }
            }

            return result.ToString().TrimEnd('X');
        }


        //DES Method
        public class DES
        {
            private static readonly int[] InitialPermutation =
            {
                58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7
            };

            private static readonly int[] FinalPermutation =
            {
                40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25
            };

            private static ulong InitialPermutationFunc(ulong input)
            {
                ulong permuted = 0;
                for (int i = 0; i < 64; i++)
                {
                    permuted <<= 1;
                    permuted |= (input >> (64 - InitialPermutation[i])) & 1;
                }
                return permuted;
            }

            private static ulong FinalPermutationFunc(ulong input)
            {
                ulong permuted = 0;
                for (int i = 0; i < 64; i++)
                {
                    permuted <<= 1;
                    permuted |= (input >> (64 - FinalPermutation[i])) & 1;
                }
                return permuted;
            }

            private static ulong FeistelFunction(ulong rightHalf, ulong key)
            {
                return (rightHalf ^ key) & 0xFFFFFFFF;
            }

            public static ulong EncryptBlock(ulong plaintext, ulong key)
            {
                ulong permuted = InitialPermutationFunc(plaintext);
                uint left = (uint)(permuted >> 32);
                uint right = (uint)(permuted & 0xFFFFFFFF);

                for (int i = 0; i < 16; i++)
                {
                    uint newRight = left ^ (uint)FeistelFunction(right, key);
                    left = right;
                    right = newRight;
                }

                ulong combined = ((ulong)right << 32) | left;
                return FinalPermutationFunc(combined);
            }

            public static ulong DecryptBlock(ulong ciphertext, ulong key)
            {
                ulong permuted = InitialPermutationFunc(ciphertext);
                uint left = (uint)(permuted >> 32);
                uint right = (uint)(permuted & 0xFFFFFFFF);

                for (int i = 15; i >= 0; i--)
                {
                    uint newRight = right;
                    right = left ^ (uint)FeistelFunction(right, key); // Use right for Feistel
                    left = newRight;
                }

                ulong combined = ((ulong)right << 32) | left;
                return FinalPermutationFunc(combined);
            }

            // Add PKCS7 padding to ensure the plaintext length is a multiple of 8
            private static byte[] AddPadding(byte[] input)
            {
                int padLength = 8 - (input.Length % 8);
                byte[] paddedInput = new byte[input.Length + padLength];
                Array.Copy(input, paddedInput, input.Length);
                for (int i = input.Length; i < paddedInput.Length; i++)
                {
                    paddedInput[i] = (byte)padLength; // PKCS7 padding
                }
                return paddedInput;
            }

            // Remove padding after decryption
            private static byte[] RemovePadding(byte[] input)
            {
                int padLength = input[input.Length - 1];
                byte[] unpaddedInput = new byte[input.Length - padLength];
                Array.Copy(input, unpaddedInput, unpaddedInput.Length);
                return unpaddedInput;
            }

            public static byte[] Encrypt(byte[] plaintext, byte[] key)
            {
                if (key.Length != 8)
                    throw new ArgumentException("Key must be 8 bytes long.");

                byte[] paddedPlaintext = AddPadding(plaintext);
                byte[] ciphertext = new byte[paddedPlaintext.Length];

                for (int i = 0; i < paddedPlaintext.Length; i += 8)
                {
                    ulong block = BitConverter.ToUInt64(paddedPlaintext, i);
                    ulong encryptedBlock = EncryptBlock(block, BitConverter.ToUInt64(key, 0));
                    Array.Copy(BitConverter.GetBytes(encryptedBlock), 0, ciphertext, i, 8);
                }

                return ciphertext;
            }

            public static byte[] Decrypt(byte[] ciphertext, byte[] key)
            {
                if (key.Length != 8)
                    throw new ArgumentException("Key must be 8 bytes long.");

                byte[] plaintext = new byte[ciphertext.Length];

                for (int i = 0; i < ciphertext.Length; i += 8)
                {
                    ulong block = BitConverter.ToUInt64(ciphertext, i);
                    ulong decryptedBlock = DecryptBlock(block, BitConverter.ToUInt64(key, 0));
                    Array.Copy(BitConverter.GetBytes(decryptedBlock), 0, plaintext, i, 8);
                }

                return RemovePadding(plaintext);
            }
        }


        public class AES
        {
            // AES-128 parameters (16-byte key)
            private const int Nb = 4;   // Number of columns (32-bit words) comprising the state
            private const int Nk = 4;   // Key length (in 32-bit words)
            private const int Nr = 10;  // Number of rounds

            // S-box table
            private static readonly byte[] sbox = new byte[256] {
                0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
                0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
                0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
                0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
                0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
                0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
                0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
                0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
                0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
                0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
                0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
                0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
                0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
                0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
                0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
                0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
                0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
            };

            // Inverse S-box table
            private static readonly byte[] invSbox = new byte[256] {
                0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,
                0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
                0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,
                0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
                0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,
                0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
                0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,
                0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
                0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,
                0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
                0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,
                0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
                0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,
                0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
                0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,
                0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
                0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,
                0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
                0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,
                0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
                0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,
                0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
                0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,
                0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
                0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,
                0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
                0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,
                0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
                0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,
                0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
                0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,
                0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
            };

            // Rcon for key expansion
            private static readonly byte[] Rcon = new byte[11] {
                0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
            };

            // Key expansion: from 16-byte key to 176 bytes
            private static byte[] KeyExpansion(byte[] key)
            {
                byte[] expandedKey = new byte[176];
                Array.Copy(key, expandedKey, 16);
                int bytesGenerated = 16;
                int rconIteration = 1;
                byte[] temp = new byte[4];

                while (bytesGenerated < 176)
                {
                    for (int i = 0; i < 4; i++)
                        temp[i] = expandedKey[bytesGenerated - 4 + i];

                    if (bytesGenerated % 16 == 0)
                    {
                        // Rotate left
                        byte t = temp[0];
                        temp[0] = temp[1];
                        temp[1] = temp[2];
                        temp[2] = temp[3];
                        temp[3] = t;
                        // Substitute using sbox
                        for (int i = 0; i < 4; i++)
                            temp[i] = sbox[temp[i]];
                        temp[0] ^= Rcon[rconIteration];
                        rconIteration++;
                    }

                    for (int i = 0; i < 4; i++)
                    {
                        expandedKey[bytesGenerated] = (byte)(expandedKey[bytesGenerated - 16] ^ temp[i]);
                        bytesGenerated++;
                    }
                }
                return expandedKey;
            }

            // --- AES Rounds operations ---
            private static void SubBytes(byte[,] state)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < Nb; j++)
                        state[i, j] = sbox[state[i, j]];
            }

            private static void InvSubBytes(byte[,] state)
            {
                for (int i = 0; i < 4; i++)
                    for (int j = 0; j < Nb; j++)
                        state[i, j] = invSbox[state[i, j]];
            }

            private static void ShiftRows(byte[,] state)
            {
                byte temp;
                // Row 1: shift left by 1
                temp = state[1, 0];
                state[1, 0] = state[1, 1];
                state[1, 1] = state[1, 2];
                state[1, 2] = state[1, 3];
                state[1, 3] = temp;
                // Row 2: shift left by 2
                temp = state[2, 0];
                state[2, 0] = state[2, 2];
                state[2, 2] = temp;
                temp = state[2, 1];
                state[2, 1] = state[2, 3];
                state[2, 3] = temp;
                // Row 3: shift left by 3 (or right by 1)
                temp = state[3, 3];
                state[3, 3] = state[3, 2];
                state[3, 2] = state[3, 1];
                state[3, 1] = state[3, 0];
                state[3, 0] = temp;
            }

            private static void InvShiftRows(byte[,] state)
            {
                byte temp;
                // Row 1: shift right by 1
                temp = state[1, 3];
                state[1, 3] = state[1, 2];
                state[1, 2] = state[1, 1];
                state[1, 1] = state[1, 0];
                state[1, 0] = temp;
                // Row 2: shift right by 2
                temp = state[2, 0];
                state[2, 0] = state[2, 2];
                state[2, 2] = temp;
                temp = state[2, 1];
                state[2, 1] = state[2, 3];
                state[2, 3] = temp;
                // Row 3: shift right by 3 (or left by 1)
                temp = state[3, 0];
                state[3, 0] = state[3, 1];
                state[3, 1] = state[3, 2];
                state[3, 2] = state[3, 3];
                state[3, 3] = temp;
            }

            private static byte Multiply(byte a, byte b)
            {
                byte p = 0;
                for (int counter = 0; counter < 8; counter++)
                {
                    if ((b & 1) != 0)
                        p ^= a;
                    bool hi_bit_set = (a & 0x80) != 0;
                    a <<= 1;
                    if (hi_bit_set)
                        a ^= 0x1B;
                    b >>= 1;
                }
                return p;
            }

            private static void MixColumns(byte[,] state)
            {
                for (int c = 0; c < Nb; c++)
                {
                    byte a0 = state[0, c];
                    byte a1 = state[1, c];
                    byte a2 = state[2, c];
                    byte a3 = state[3, c];
                    state[0, c] = (byte)(Multiply(0x02, a0) ^ Multiply(0x03, a1) ^ a2 ^ a3);
                    state[1, c] = (byte)(a0 ^ Multiply(0x02, a1) ^ Multiply(0x03, a2) ^ a3);
                    state[2, c] = (byte)(a0 ^ a1 ^ Multiply(0x02, a2) ^ Multiply(0x03, a3));
                    state[3, c] = (byte)(Multiply(0x03, a0) ^ a1 ^ a2 ^ Multiply(0x02, a3));
                }
            }

            private static void InvMixColumns(byte[,] state)
            {
                for (int c = 0; c < Nb; c++)
                {
                    byte a0 = state[0, c];
                    byte a1 = state[1, c];
                    byte a2 = state[2, c];
                    byte a3 = state[3, c];
                    state[0, c] = (byte)(Multiply(0x0e, a0) ^ Multiply(0x0b, a1) ^ Multiply(0x0d, a2) ^ Multiply(0x09, a3));
                    state[1, c] = (byte)(Multiply(0x09, a0) ^ Multiply(0x0e, a1) ^ Multiply(0x0b, a2) ^ Multiply(0x0d, a3));
                    state[2, c] = (byte)(Multiply(0x0d, a0) ^ Multiply(0x09, a1) ^ Multiply(0x0e, a2) ^ Multiply(0x0b, a3));
                    state[3, c] = (byte)(Multiply(0x0b, a0) ^ Multiply(0x0d, a1) ^ Multiply(0x09, a2) ^ Multiply(0x0e, a3));
                }
            }

            private static void AddRoundKey(byte[,] state, byte[] expandedKey, int round)
            {
                for (int c = 0; c < Nb; c++)
                {
                    for (int r = 0; r < 4; r++)
                    {
                        state[r, c] ^= expandedKey[round * 16 + c * 4 + r];
                    }
                }
            }

            // Encrypt a single 16-byte block
            private static byte[] EncryptBlock(byte[] input, byte[] expandedKey)
            {
                byte[,] state = new byte[4, Nb];
                for (int i = 0; i < 16; i++)
                    state[i % 4, i / 4] = input[i];

                AddRoundKey(state, expandedKey, 0);

                for (int round = 1; round < Nr; round++)
                {
                    SubBytes(state);
                    ShiftRows(state);
                    MixColumns(state);
                    AddRoundKey(state, expandedKey, round);
                }

                SubBytes(state);
                ShiftRows(state);
                AddRoundKey(state, expandedKey, Nr);

                byte[] output = new byte[16];
                for (int i = 0; i < 16; i++)
                    output[i] = state[i % 4, i / 4];

                return output;
            }

            // Decrypt a single 16-byte block
            private static byte[] DecryptBlock(byte[] input, byte[] expandedKey)
            {
                byte[,] state = new byte[4, Nb];
                for (int i = 0; i < 16; i++)
                    state[i % 4, i / 4] = input[i];

                AddRoundKey(state, expandedKey, Nr);

                for (int round = Nr - 1; round >= 1; round--)
                {
                    InvShiftRows(state);
                    InvSubBytes(state);
                    AddRoundKey(state, expandedKey, round);
                    InvMixColumns(state);
                }

                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, expandedKey, 0);

                byte[] output = new byte[16];
                for (int i = 0; i < 16; i++)
                    output[i] = state[i % 4, i / 4];

                return output;
            }

            // PKCS7 padding methods
            private static byte[] AddPadding(byte[] input)
            {
                int padLength = 16 - (input.Length % 16);
                byte[] padded = new byte[input.Length + padLength];
                Array.Copy(input, padded, input.Length);
                for (int i = input.Length; i < padded.Length; i++)
                    padded[i] = (byte)padLength;
                return padded;
            }

            private static byte[] RemovePadding(byte[] input)
            {
                int padLength = input[input.Length - 1];
                byte[] output = new byte[input.Length - padLength];
                Array.Copy(input, output, output.Length);
                return output;
            }

            // Public methods to encrypt/decrypt byte arrays
            public static byte[] Encrypt(byte[] plaintext, byte[] key)
            {
                if (key.Length != 16)
                    throw new ArgumentException("Key must be 16 bytes long for AES-128.");
                byte[] padded = AddPadding(plaintext);
                byte[] expandedKey = KeyExpansion(key);
                byte[] ciphertext = new byte[padded.Length];
                for (int i = 0; i < padded.Length; i += 16)
                {
                    byte[] block = new byte[16];
                    Array.Copy(padded, i, block, 0, 16);
                    byte[] encryptedBlock = EncryptBlock(block, expandedKey);
                    Array.Copy(encryptedBlock, 0, ciphertext, i, 16);
                }
                return ciphertext;
            }

            public static byte[] Decrypt(byte[] ciphertext, byte[] key)
            {
                if (key.Length != 16)
                    throw new ArgumentException("Key must be 16 bytes long for AES-128.");
                byte[] expandedKey = KeyExpansion(key);
                byte[] plaintextPadded = new byte[ciphertext.Length];
                for (int i = 0; i < ciphertext.Length; i += 16)
                {
                    byte[] block = new byte[16];
                    Array.Copy(ciphertext, i, block, 0, 16);
                    byte[] decryptedBlock = DecryptBlock(block, expandedKey);
                    Array.Copy(decryptedBlock, 0, plaintextPadded, i, 16);
                }
                return RemovePadding(plaintextPadded);
            }
        }

        public class RC4
        {
            /// <summary>
            /// Encrypts (or decrypts) the input data using RC4 with the specified key.
            /// </summary>
            /// <param name="input">Input data as a byte array.</param>
            /// <param name="key">Key as a byte array.</param>
            /// <returns>Output byte array after applying RC4.</returns>
            public static byte[] Encrypt(byte[] input, byte[] key)
            {
                // Initialize S array with values 0 through 255
                byte[] S = new byte[256];
                for (int i = 0; i < 256; i++)
                {
                    S[i] = (byte)i;
                }

                // Key-Scheduling Algorithm (KSA)
                int j = 0;
                for (int i = 0; i < 256; i++)
                {
                    j = (j + S[i] + key[i % key.Length]) & 0xFF;
                    // Swap S[i] and S[j]
                    byte temp = S[i];
                    S[i] = S[j];
                    S[j] = temp;
                }

                // Pseudo-Random Generation Algorithm (PRGA)
                byte[] output = new byte[input.Length];
                int iIndex = 0;
                int jIndex = 0;
                for (int k = 0; k < input.Length; k++)
                {
                    iIndex = (iIndex + 1) & 0xFF;
                    jIndex = (jIndex + S[iIndex]) & 0xFF;
                    // Swap S[iIndex] and S[jIndex]
                    byte temp = S[iIndex];
                    S[iIndex] = S[jIndex];
                    S[jIndex] = temp;
                    byte K = S[(S[iIndex] + S[jIndex]) & 0xFF];
                    output[k] = (byte)(input[k] ^ K);
                }
                return output;
            }

            /// <summary>
            /// Decrypts the input data using RC4 with the specified key.
            /// Note: RC4 decryption is identical to encryption.
            /// </summary>
            public static byte[] Decrypt(byte[] input, byte[] key)
            {
                return Encrypt(input, key);
            }
        }


        //RSA 
        public static class RSA
        {
            /// <summary>
            /// Encrypts the plaintext using RSA with the provided public key.
            /// The key must be provided as a comma-separated string "n,e".
            /// This method splits the plaintext into blocks so that larger messages can be encrypted.
            /// </summary>
            ///

            public static void GenerateKeyPair(int keySizeBits, out string publicKey, out string privateKey)
            {
                // Generate two large prime numbers, p and q
                BigInteger p = GenerateLargePrime(keySizeBits / 2);
                BigInteger q = GenerateLargePrime(keySizeBits / 2);

                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);

                BigInteger e = 65537; // Commonly used public exponent

                // Ensure e and phi are coprime
                while (GCD(e, phi) != 1)
                {
                    e += 2;
                }

                BigInteger d = ModInverse(e, phi);

                publicKey = $"{n},{e}";
                privateKey = $"{n},{d}";
            }


            private static BigInteger GenerateLargePrime(int bitLength)
            {
                Random rnd = new Random();
                BigInteger p;

                do
                {
                    byte[] bytes = new byte[bitLength / 8 + 1];
                    rnd.NextBytes(bytes);
                    bytes[bytes.Length - 1] = 0; // ensure non-negative
                    p = new BigInteger(bytes);
                    p |= 1; // make it odd

                } while (!IsProbablyPrime(p, 10));

                return p;
            }

            private static bool IsProbablyPrime(BigInteger value, int k)
            {
                if (value < 2) return false;
                if (value == 2 || value == 3) return true;
                if (value % 2 == 0) return false;

                BigInteger d = value - 1;
                int s = 0;
                while (d % 2 == 0)
                {
                    d /= 2;
                    s++;
                }

                Random rng = new Random();
                for (int i = 0; i < k; i++)
                {
                    BigInteger a = 2 + (BigInteger)rng.Next() % (value - 3);
                    BigInteger x = BigInteger.ModPow(a, d, value);

                    if (x == 1 || x == value - 1) continue;

                    bool passed = false;
                    for (int r = 1; r < s; r++)
                    {
                        x = BigInteger.ModPow(x, 2, value);
                        if (x == value - 1)
                        {
                            passed = true;
                            break;
                        }
                    }

                    if (!passed) return false;
                }

                return true;
            }

            private static BigInteger GCD(BigInteger a, BigInteger b)
            {
                while (b != 0)
                {
                    BigInteger temp = b;
                    b = a % b;
                    a = temp;
                }
                return a;
            }

            private static BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                BigInteger m0 = m, t, q;
                BigInteger x0 = 0, x1 = 1;

                if (m == 1) return 0;

                while (a > 1)
                {
                    q = a / m;
                    t = m;
                    m = a % m;
                    a = t;
                    t = x0;
                    x0 = x1 - q * x0;
                    x1 = t;
                }

                return x1 < 0 ? x1 + m0 : x1;
            }

            public static string Encrypt(string plaintext, string key)
            {
                // Parse the key.
                var parts = key.Split(',');
                if (parts.Length != 2)
                    throw new ArgumentException("Invalid RSA public key format. Expected 'n,e'.");

                BigInteger n = BigInteger.Parse(parts[0]);
                BigInteger e = BigInteger.Parse(parts[1]);

                // Determine maximum block size in bytes so that the numeric value of the block is < n.
                // maxBlockSize = floor(log256(n))
                int maxBlockSize = (int)Math.Floor(BigInteger.Log(n, 256));
                if (maxBlockSize < 1)
                    throw new Exception("RSA modulus is too small.");

                // Convert plaintext to bytes.
                byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
                List<string> encryptedBlocks = new List<string>();

                // Process the plaintext in blocks.
                for (int i = 0; i < plaintextBytes.Length; i += maxBlockSize)
                {
                    int blockSize = Math.Min(maxBlockSize, plaintextBytes.Length - i);
                    // Create a block with an extra zero appended to ensure non-negativity.
                    byte[] block = new byte[blockSize + 1];
                    Array.Copy(plaintextBytes, i, block, 0, blockSize);
                    BigInteger m = new BigInteger(block);

                    // Encrypt the block: c = m^e mod n.
                    BigInteger c = BigInteger.ModPow(m, e, n);

                    // Convert the ciphertext block to a Base64 string.
                    byte[] cipherBlockBytes = c.ToByteArray();
                    encryptedBlocks.Add(Convert.ToBase64String(cipherBlockBytes));
                }

                // Join the encrypted blocks with a delimiter.
                return string.Join("|", encryptedBlocks);
            }

            /// <summary>
            /// Decrypts the ciphertext using RSA with the provided private key.
            /// The key must be provided as a comma-separated string "n,d".
            /// This method expects the ciphertext blocks to be separated by '|'.
            /// </summary>
            public static string Decrypt(string ciphertext, string key)
            {
                // Parse the key.
                var parts = key.Split(',');
                if (parts.Length != 2)
                    throw new ArgumentException("Invalid RSA private key format. Expected 'n,d'.");

                BigInteger n = BigInteger.Parse(parts[0]);
                BigInteger d = BigInteger.Parse(parts[1]);

                // Split the ciphertext into blocks.
                string[] blocks = ciphertext.Split('|');
                List<byte> decryptedBytes = new List<byte>();

                foreach (var block in blocks)
                {
                    byte[] cipherBlockBytes = Convert.FromBase64String(block);
                    BigInteger c = new BigInteger(cipherBlockBytes);
                    // Decrypt: m = c^d mod n.
                    BigInteger m = BigInteger.ModPow(c, d, n);

                    // Convert the BigInteger back to a byte array.
                    byte[] blockBytes = m.ToByteArray();

                    // If a trailing zero was added during encryption, remove it.
                    if (blockBytes.Length > 0 && blockBytes[blockBytes.Length - 1] == 0)
                        blockBytes = blockBytes.Take(blockBytes.Length - 1).ToArray();

                    decryptedBytes.AddRange(blockBytes);
                }

                return Encoding.UTF8.GetString(decryptedBytes.ToArray());
            }
        }

        // ECC – Elliptic Curve Cryptography (Simplified)
        public class ECC
        {
            private static readonly BigInteger a = 0;
            private static readonly BigInteger b = 7;
            private static readonly BigInteger p = BigInteger.Parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", System.Globalization.NumberStyles.HexNumber); // secp256k1
            private static readonly (BigInteger x, BigInteger y) G = (
                BigInteger.Parse("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", System.Globalization.NumberStyles.HexNumber),
                BigInteger.Parse("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", System.Globalization.NumberStyles.HexNumber)
            );

            public static void GenerateKeyPair(out string publicKey, out string privateKey)
            {
                var priv = GeneratePrivateKey();
                var pub = Multiply(G, priv);
                privateKey = priv.ToString("X");
                publicKey = $"{pub.x.ToString("X")},{pub.y.ToString("X")}";
            }

            public static string DeriveSharedKey(string privateKeyHex, string otherPublicKey)
            {
                BigInteger priv = BigInteger.Parse(privateKeyHex, System.Globalization.NumberStyles.HexNumber);
                var coords = otherPublicKey.Split(',');
                var pubX = BigInteger.Parse(coords[0], System.Globalization.NumberStyles.HexNumber);
                var pubY = BigInteger.Parse(coords[1], System.Globalization.NumberStyles.HexNumber);

                var sharedPoint = Multiply((pubX, pubY), priv);
                var sharedKeyBytes = sharedPoint.x.ToByteArray();
                return Convert.ToBase64String(sharedKeyBytes);
            }

            public static string Encrypt(string message, string sharedKeyBase64)
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] keyBytes = Convert.FromBase64String(sharedKeyBase64);

                byte[] result = new byte[messageBytes.Length];
                for (int i = 0; i < messageBytes.Length; i++)
                    result[i] = (byte)(messageBytes[i] ^ keyBytes[i % keyBytes.Length]);

                return Convert.ToBase64String(result);
            }

            public static string Decrypt(string encryptedBase64, string sharedKeyBase64)
            {
                byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
                byte[] keyBytes = Convert.FromBase64String(sharedKeyBase64);

                byte[] result = new byte[encryptedBytes.Length];
                for (int i = 0; i < encryptedBytes.Length; i++)
                    result[i] = (byte)(encryptedBytes[i] ^ keyBytes[i % keyBytes.Length]);

                return Encoding.UTF8.GetString(result);
            }

            // --- ECC math methods below

            private static BigInteger GeneratePrivateKey()
            {
                byte[] bytes = new byte[32];
                new Random().NextBytes(bytes);
                return new BigInteger(bytes) % p;
            }

            private static (BigInteger x, BigInteger y) Add((BigInteger x, BigInteger y) P, (BigInteger x, BigInteger y) Q)
            {
                if (P.x == Q.x && P.y == Q.y)
                {
                    BigInteger slope = ((3 * P.x * P.x + a) * ModInverse(2 * P.y, p)) % p;
                    BigInteger x3 = (slope * slope - 2 * P.x) % p;
                    BigInteger y3 = (slope * (P.x - x3) - P.y) % p;
                    return (Mod(x3, p), Mod(y3, p));
                }
                else
                {
                    BigInteger slope = ((Q.y - P.y) * ModInverse(Q.x - P.x, p)) % p;
                    BigInteger x3 = (slope * slope - P.x - Q.x) % p;
                    BigInteger y3 = (slope * (P.x - x3) - P.y) % p;
                    return (Mod(x3, p), Mod(y3, p));
                }
            }

            private static (BigInteger x, BigInteger y) Multiply((BigInteger x, BigInteger y) P, BigInteger k)
            {
                (BigInteger x, BigInteger y) result = (0, 0);
                (BigInteger x, BigInteger y) addend = P;

                while (k > 0)
                {
                    if ((k & 1) != 0)
                    {
                        if (result.x == 0 && result.y == 0)
                            result = addend;
                        else
                            result = Add(result, addend);
                    }

                    addend = Add(addend, addend);
                    k >>= 1;
                }

                return result;
            }

            private static BigInteger Mod(BigInteger value, BigInteger m)
            {
                var r = value % m;
                return r < 0 ? r + m : r;
            }

            private static BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                (BigInteger lm, BigInteger hm) = (1, 0);
                (BigInteger low, BigInteger high) = (Mod(a, m), m);

                while (low > 1)
                {
                    BigInteger r = high / low;
                    (lm, hm) = (hm - lm * r, lm);
                    (low, high) = (high - low * r, low);
                }

                return Mod(lm, m);
            }

        }

        //DH Technique
        public class DH
        {
            // For demonstration only. In real applications, p and g must be very large.
            public static readonly BigInteger p = 23;  // A small prime
            public static readonly BigInteger g = 5;   // A generator

            /// <summary>
            /// Generates a random private key in the range [2, p-2].
            /// </summary>
            public static BigInteger GeneratePrivateKey()
            {
                Random rnd = new Random();
                return new BigInteger(rnd.Next(2, (int)p - 1));
            }

            /// <summary>
            /// Generates a public key from the private key using: g^privateKey mod p.
            /// Returns the value as a hex string.
            /// </summary>
            public static string GeneratePublicKey(BigInteger privateKey)
            {
                BigInteger publicKey = BigInteger.ModPow(g, privateKey, p);
                return publicKey.ToString("X");
            }

            /// <summary>
            /// Derives the shared secret using the other party’s public key and your private key.
            /// Computes (otherPublicKey ^ privateKey mod p) and returns it as a hex string.
            /// </summary>
            public static string DeriveSharedSecret(string otherPublicKeyHex, BigInteger privateKey)
            {
                BigInteger otherPublicKey = BigInteger.Parse(otherPublicKeyHex, NumberStyles.HexNumber);
                BigInteger sharedSecret = BigInteger.ModPow(otherPublicKey, privateKey, p);
                // Convert to hex string and pad with a leading zero if odd length.
                string sharedSecretHex = sharedSecret.ToString("X");
                if (sharedSecretHex.Length % 2 != 0)
                {
                    sharedSecretHex = "0" + sharedSecretHex;
                }
                return sharedSecretHex;
            }


            /// <summary>
            /// Encrypts a plaintext message using a shared secret (provided as a hex string).
            /// The encryption is a simple XOR of the message bytes with the key bytes.
            /// </summary>
            public static string Encrypt(string message, string sharedSecretHex)
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] keyBytes = HexStringToBytes(sharedSecretHex);
                byte[] result = new byte[messageBytes.Length];

                for (int i = 0; i < messageBytes.Length; i++)
                    result[i] = (byte)(messageBytes[i] ^ keyBytes[i % keyBytes.Length]);

                return Convert.ToBase64String(result);
            }

            /// <summary>
            /// Decrypts ciphertext (produced by Encrypt) using the same shared secret.
            /// </summary>
            public static string Decrypt(string encryptedBase64, string sharedSecretHex)
            {
                byte[] cipherBytes = Convert.FromBase64String(encryptedBase64);
                byte[] keyBytes = HexStringToBytes(sharedSecretHex);
                byte[] result = new byte[cipherBytes.Length];

                for (int i = 0; i < cipherBytes.Length; i++)
                    result[i] = (byte)(cipherBytes[i] ^ keyBytes[i % keyBytes.Length]);

                return Encoding.UTF8.GetString(result);
            }

            /// <summary>
            /// Converts a hex string to a byte array.
            /// </summary>
            private static byte[] HexStringToBytes(string hex)
            {
                if (hex == null)
                    throw new ArgumentNullException(nameof(hex));
                int numberChars = hex.Length;
                byte[] bytes = new byte[numberChars / 2];
                for (int i = 0; i < numberChars; i += 2)
                    bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
                return bytes;
            }
        }

        //SHA Technique
        public class SHA
        {
            /// <summary>
            /// Computes a simple hash of the input string.
            /// (This is a rudimentary hash and NOT equivalent to SHA-256.)
            /// </summary>
            public static string ComputeHash(string input)
            {
                BigInteger hash = 0;
                BigInteger mod = 997; // A small modulus for demonstration.
                foreach (char c in input)
                {
                    hash = (hash * 31 + c) % mod;
                }
                return hash.ToString("X");  // Return as hex string.
            }

            /// <summary>
            /// There is no decryption for a hash function.
            /// </summary>
            public static string Decrypt(string ciphertext)
            {
                throw new NotSupportedException("Hash functions are one-way; decryption is not supported.");
            }
        }


        //public class CustomSHA256
        //{
        //    // SHA-256 constants: the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
        //    private static readonly uint[] k = new uint[]
        //    {
        //0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        //0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        //0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        //0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        //0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        //0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        //0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        //0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        //0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        //0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        //0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        //0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        //0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        //0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        //0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        //0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
        //    };

        //    // Computes the SHA-256 hash as a hex string.
        //    public static string ComputeHash(string input)
        //    {
        //        byte[] bytes = Encoding.UTF8.GetBytes(input);
        //        // Pre-processing: padding the input
        //        int originalLength = bytes.Length;
        //        // Calculate the bit length of the original message
        //        ulong bitLength = (ulong)originalLength * 8;

        //        // Append a '1' bit (0x80), then pad with zeros until message length (in bytes) ≡ 56 mod 64
        //        int padLength = (56 - ((originalLength + 1) % 64) + 64) % 64;
        //        byte[] padded = new byte[originalLength + 1 + padLength + 8];
        //        Buffer.BlockCopy(bytes, 0, padded, 0, originalLength);
        //        padded[originalLength] = 0x80; // append the 1 bit (and seven 0 bits)
        //                                       // The remaining pad bytes are already zero by default

        //        // Append the original length as a 64-bit big-endian integer
        //        for (int i = 0; i < 8; i++)
        //        {
        //            padded[padded.Length - 1 - i] = (byte)(bitLength >> (8 * i));
        //        }

        //        // Initialize hash values: the first 32 bits of the fractional parts of the square roots of the first 8 primes.
        //        uint h0 = 0x6a09e667;
        //        uint h1 = 0xbb67ae85;
        //        uint h2 = 0x3c6ef372;
        //        uint h3 = 0xa54ff53a;
        //        uint h4 = 0x510e527f;
        //        uint h5 = 0x9b05688c;
        //        uint h6 = 0x1f83d9ab;
        //        uint h7 = 0x5be0cd19;

        //        // Process the padded message in successive 512-bit (64-byte) chunks
        //        for (int i = 0; i < padded.Length; i += 64)
        //        {
        //            uint[] w = new uint[64];
        //            // Copy chunk into first 16 words w[0..15] (big-endian)
        //            for (int j = 0; j < 16; j++)
        //            {
        //                int index = i + j * 4;
        //                w[j] = ((uint)padded[index] << 24) | ((uint)padded[index + 1] << 16) |
        //                       ((uint)padded[index + 2] << 8) | ((uint)padded[index + 3]);
        //            }
        //            // Extend the first 16 words into the remaining 48 words w[16..63]
        //            for (int j = 16; j < 64; j++)
        //            {
        //                uint s0 = RightRotate(w[j - 15], 7) ^ RightRotate(w[j - 15], 18) ^ (w[j - 15] >> 3);
        //                uint s1 = RightRotate(w[j - 2], 17) ^ RightRotate(w[j - 2], 19) ^ (w[j - 2] >> 10);
        //                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
        //            }

        //            // Initialize working variables to current hash value
        //            uint a = h0;
        //            uint b = h1;
        //            uint c = h2;
        //            uint d = h3;
        //            uint e = h4;
        //            uint f = h5;
        //            uint g = h6;
        //            uint h = h7;

        //            // Compression function main loop:
        //            for (int j = 0; j < 64; j++)
        //            {
        //                uint S1 = RightRotate(e, 6) ^ RightRotate(e, 11) ^ RightRotate(e, 25);
        //                uint ch = (e & f) ^ ((~e) & g);
        //                uint temp1 = h + S1 + ch + k[j] + w[j];
        //                uint S0 = RightRotate(a, 2) ^ RightRotate(a, 13) ^ RightRotate(a, 22);
        //                uint maj = (a & b) ^ (a & c) ^ (b & c);
        //                uint temp2 = S0 + maj;

        //                h = g;
        //                g = f;
        //                f = e;
        //                e = d + temp1;
        //                d = c;
        //                c = b;
        //                b = a;
        //                a = temp1 + temp2;
        //            }

        //            // Add the compressed chunk to the current hash value
        //            h0 += a;
        //            h1 += b;
        //            h2 += c;
        //            h3 += d;
        //            h4 += e;
        //            h5 += f;
        //            h6 += g;
        //            h7 += h;
        //        }
        //        // Produce the final hash value (big-endian) as a hexadecimal string.
        //        return h0.ToString("x8") + h1.ToString("x8") + h2.ToString("x8") + h3.ToString("x8") +
        //               h4.ToString("x8") + h5.ToString("x8") + h6.ToString("x8") + h7.ToString("x8");
        //    }

        //    // Utility: Right rotate a 32-bit unsigned integer by the specified number of bits.
        //    private static uint RightRotate(uint value, int bits)
        //    {
        //        return (value >> bits) | (value << (32 - bits));
        //    }
        //}

            //DSA Technique
            public class DSA
        {
            // Demo parameters (totally insecure for production):
            // p and q must be primes with q dividing p-1.
            public static readonly BigInteger p = 23;  // a small prime
            public static readonly BigInteger q = 11;  // q divides p-1 (since 11 divides 22)
            public static readonly BigInteger g = 2;   // a generator

            /// <summary>
            /// Generates a DSA private key in the range [1, q-1].
            /// </summary>
            public static BigInteger GeneratePrivateKey()
            {
                Random rnd = new Random();
                return new BigInteger(rnd.Next(1, (int)q));
            }

            /// <summary>
            /// Generates a DSA public key: y = g^x mod p.
            /// Returns y as a decimal string.
            /// </summary>
            public static string GeneratePublicKey(BigInteger privateKey)
            {
                BigInteger y = BigInteger.ModPow(g, privateKey, p);
                return y.ToString();
            }

            /// <summary>
            /// Signs a message using the DSA private key.
            /// Returns a tuple (r, s) as strings.
            /// </summary>
            public static (string r, string s) Sign(string message, BigInteger privateKey)
            {
                BigInteger H = ComputeHash(message);
                Random rnd = new Random();
                // Choose a random k in [1, q-1]
                BigInteger k = new BigInteger(rnd.Next(1, (int)q));
                // r = (g^k mod p) mod q
                BigInteger r = BigInteger.ModPow(g, k, p) % q;
                BigInteger kInv = ModInverse(k, q);
                // s = (kInv * (H + x*r)) mod q
                BigInteger s = (kInv * (H + privateKey * r)) % q;
                if (s < 0)
                    s += q;
                return (r.ToString(), s.ToString());
            }

            /// <summary>
            /// Verifies a DSA signature.
            /// </summary>
            public static bool Verify(string message, string rStr, string sStr, string publicKeyStr)
            {
                BigInteger r = BigInteger.Parse(rStr);
                BigInteger s = BigInteger.Parse(sStr);
                BigInteger y = BigInteger.Parse(publicKeyStr);
                BigInteger H = ComputeHash(message);
                BigInteger w = ModInverse(s, q);
                BigInteger u1 = (H * w) % q;
                BigInteger u2 = (r * w) % q;
                BigInteger v = (BigInteger.ModPow(g, u1, p) * BigInteger.ModPow(y, u2, p)) % p;
                v %= q;
                return v == r;
            }

            /// <summary>
            /// A simple hash function for DSA that computes a hash modulo q.
            /// </summary>
            private static BigInteger ComputeHash(string input)
            {
                BigInteger hash = 0;
                foreach (char c in input)
                {
                    hash = (hash * 31 + c) % q;
                }
                return hash;
            }

            /// <summary>
            /// Computes the modular inverse of a modulo m.
            /// </summary>
            private static BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                BigInteger m0 = m, t, q;
                BigInteger x0 = 0, x1 = 1;
                if (m == 1)
                    return 0;
                while (a > 1)
                {
                    q = a / m;
                    t = m;
                    m = a % m;
                    a = t;
                    t = x0;
                    x0 = x1 - q * x0;
                    x1 = t;
                }
                if (x1 < 0)
                    x1 += m0;
                return x1;
            }
        }

    }
}
