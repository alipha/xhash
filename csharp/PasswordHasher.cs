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
    public enum HashError
    {
        Success = 0,
        NullHandle = -1,
        HandleNotInitialized = -2,
        InvalidIterations = -3,
        InvalidMemoryMultiplier = -4,
        NullDigest = -5,
        NullData = -6,
        NullSalt = -7,
        MallocFailed = -8
    }

    [StructLayout(LayoutKind.Sequential)]
    struct Settings
    {
        public IntPtr system_salt;
        public int system_salt_len;
        public int iterations;
        public int multiplier;
        public int mixing_iterations;
        public int hash_array_size;
        public IntPtr hash_array;
    }


    public class PasswordHasher : IDisposable
    {
        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int xhash_init(ref Settings handle, byte[] system_salt, int system_salt_len, int iterations, int memory_multiplier_bits);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
        private static extern int xhash_init_defaults(ref Settings handle, byte[] system_salt, int system_salt_len);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern int xhash(ref Settings handle, byte[] digest, byte[] data, int data_len, byte[] salt, int salt_len, int free_after);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern int xhash_text(ref Settings handle, byte[] base64_digest, byte[] password, byte[] user_salt, int free_after);

        [DllImport("xhash.dll", CallingConvention=CallingConvention.Cdecl)]
	    private static extern void xhash_free(ref Settings handle);


        private Settings xhash_settings;

        public int HashByteSize { get { return 64; } }

        public int MemoryUsage { get { return xhash_settings.hash_array_size * HashByteSize; } }


        // memoryMultiplier has a range of [0, 4]
        // iterations * 2^memoryMultiplier < 2^24 (16 million)
        public PasswordHasher(string systemSalt = "", int iterations = 12288, int memoryMultiplier = 4)
        {
            byte[] systemSaltBytes = Encoding.ASCII.GetBytes(systemSalt);

            xhash_settings = new Settings();
            var error = (HashError)xhash_init(ref xhash_settings, systemSaltBytes, systemSaltBytes.Length, iterations, memoryMultiplier);

            switch(error)
            {
                case HashError.Success:                 break;
                case HashError.InvalidIterations:       throw new IterationsOutOfRangeException(iterations);
                case HashError.InvalidMemoryMultiplier: throw new MemoryMultiplierOutOfRangeException(memoryMultiplier);
                default:                                throw new Exception("Error in PasswordHasher constructor: " + error);
            }              
        }

 
        public string Hash(string password, string userSalt)
        {
            byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
            byte[] userSaltBytes = Encoding.ASCII.GetBytes(userSalt);
            byte[] digest = new byte[64];

            var error = (HashError)xhash(ref xhash_settings, digest, passwordBytes, passwordBytes.Length, userSaltBytes, userSaltBytes.Length, 0);

            if (error != HashError.Success)
                throw new Exception("Error in PasswordHasher.Hash: " + error);

            return Convert.ToBase64String(digest);
        }
 
 
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


    public class IterationsOutOfRangeException : ArgumentOutOfRangeException
    {
        public IterationsOutOfRangeException(int provided) : base("iterations", provided,
                "Argument iterations to LiphSoft.Encryption.PasswordHasher must be equal to or greater than 3. Provided: " + provided)
        { }
    }

    public class MemoryMultiplierOutOfRangeException : ArgumentOutOfRangeException
    {
        public MemoryMultiplierOutOfRangeException(int provided) : base("memoryMultiplier", provided,
                "Argument memoryMultiplier to LiphSoft.Encryption.PasswordHasher must have a range of 0 to 4. Provided: " + provided)
        { }
    }
}
