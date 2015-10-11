/*
The MIT License (MIT)

Copyright (c) 2015 Kevin Spinar (Alipha)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace XHash
{
    /* The errors that the C library can report. However, this C# wrapper controls what is sent to
     * the C library, and so, only Success, InvalidMemoryBits and MallocFailed are actually used,
     * and the user never sees them. Instead, PasswordHasher will throw exceptions */ 
    enum HashError
    {
        Success = 0,
        NullHandle = -1,
        HandleNotInitialized = -2,
        InvalidMemoryBits = -3,
        NullDigest = -4,
        NullData = -5,
        NullSalt = -6,
        MallocFailed = -7
    }

    /* Information to pass to the C library. Not relevant for the user */
    [StructLayout(LayoutKind.Sequential)]
    struct Settings
    {
        public IntPtr system_salt;
        public int system_salt_len;
        public int mixing_iterations;
        public int fill_amount;
        public int memory_blocks;
        public int memory_usage;
        public IntPtr hash_array;
    }


    public class PasswordHasher : IDisposable
    {
        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int xhash_init(ref Settings handle, byte[] system_salt, int system_salt_len, int memory_bits, int additional_iterations);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int xhash_init_defaults(ref Settings handle, byte[] system_salt, int system_salt_len);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern int xhash(ref Settings handle, byte[] digest, byte[] data, int data_len, byte[] salt, int salt_len, int free_after);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern int xhash_text(ref Settings handle, byte[] base64_digest, byte[] password, byte[] user_salt, int free_after);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern void xhash_free(ref Settings handle);


        private Settings xhash_settings;


        public const int DefaultMemoryBits = 22;
        public const int MinMemoryBits = 10;
        public const int MaxMemoryBits = 31;

        public const int DigestBits = 6;
        public const int DigestSize = (1 << DigestBits);    // The output of PasswordHasher.Hash is a Base64 encoding of a 64-byte hash (digest)


        // How much memory the hash function uses with specified constructor parameters (same as: 1 << memoryBits)
        public int MemoryUsage { get { return xhash_settings.memory_usage; } } 


        // Initialize the password hasher with the specified system salt, memoryBits, and additional iterations to perform.
        // Use GenerateSalt() to create the system salt and store it somewhere separate from the per-user salt.
        // The PasswordHasher will allocate (1 << memoryBits) bytes of memory and perform (1 << (memoryBits - 9)) iterations by default.
        // E.g., with the memoryBits default of 22, then 4 MB of memory is allocated and 8192 iterations are performed.
        public PasswordHasher(string systemSalt = "", int memoryBits = DefaultMemoryBits, int additionalIterations = 0)
        {
            byte[] systemSaltBytes = Encoding.ASCII.GetBytes(systemSalt);

            xhash_settings = new Settings();
            var error = (HashError)xhash_init(ref xhash_settings, systemSaltBytes, systemSaltBytes.Length, memoryBits, additionalIterations);

            switch(error)
            {
                case HashError.Success:           break;
                case HashError.InvalidMemoryBits: throw new MemoryBitsOutOfRangeException(memoryBits);
                case HashError.MallocFailed:      throw new InsufficientMemoryException("XHash.PasswordHasher was unable to allocate " + (1 << memoryBits) + " bytes of memory to perform the hashing.");
                default:                          throw new Exception("Error in PasswordHasher constructor: " + error);
            }              
        }

 
        // Hash the specified password with the specified user salt and return a base64-encoded hash (88 characters after base64-encoding)
        // Use GenerateSalt() to create the user salt
        public string Hash(string password, string userSalt)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] userSaltBytes = Encoding.ASCII.GetBytes(userSalt);
            byte[] digest = new byte[DigestSize];

            var error = (HashError)xhash(ref xhash_settings, digest, passwordBytes, passwordBytes.Length, userSaltBytes, userSaltBytes.Length, 0);

            if (error != HashError.Success)
                throw new Exception("Error in PasswordHasher.Hash: " + error);

            return Convert.ToBase64String(digest);
        }
 
 
        // Not used in password hashing, but a convenience function for generating 256-bit salts to use for system salt and user salt (base64-encoded)
        // Returns 44 characters after encoding
        public static string GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var data = new byte[32];
                rng.GetBytes(data);
                return Convert.ToBase64String(data);
            }
        }


        public void Dispose()
        {
            xhash_free(ref xhash_settings);
        }
    }


    public class MemoryBitsOutOfRangeException : ArgumentOutOfRangeException
    {
        public MemoryBitsOutOfRangeException(int provided) : base("memoryBits", provided,
                "Argument memoryBits to LiphSoft.Encryption.PasswordHasher must have a range of 10 to 31 (default of 22). Provided: " + provided)
        { }
    }
}
