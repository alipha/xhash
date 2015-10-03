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
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
 
// The Hash algorithm is divided into two parts. First, we fill an array with
// each iterative result of a SHA512 hash of the password+salt.
// Then we "randomly" select cells in this array to hash with the running hash
// and then xor back into that cell, which makes "random" changes to the array,
// forcing the runner of this algorithm to maintain the state of the whole array
// and not being able to easily reproduce what a specific cell contains.
// We divide the number of requested iterations between the two parts such that
// there is at least twice as many iterations done in the second part as the
// first so that the array is sufficientally "mixed up"
namespace XHash.Test
{
    public class TestPasswordHasher
    {
        private const int MULTIPLIER_BITS = 4;
        private const int MULTIPLIER = (1 << MULTIPLIER_BITS);

        private string _systemSalt;
        private int _mixingIterations;
        private int _fillAmount;
        private int _memoryBlocks;

        private byte[] _hashArray;

        public int MemoryUsage { get { return _fillAmount * MULTIPLIER; } }

#if DEBUG
        public IList<string> _hashes;
        public int[] _visitCounts;
        public byte[] _originalArray;
        public byte[] __hashArray { get { return _hashArray; } }
        public int __hashArraySize { get { return _memoryBlocks; } }
        public IDictionary<string, int[]> _hashToCells;
        public IList<string>[] _hashesPerCell;
#endif
 
        // memoryMultiplier has a range of [0, 4]
        // iterations * 2^memoryMultiplier < 2^24 (16 million)
        public TestPasswordHasher(string systemSalt = "", int memoryBits = PasswordHasher.DefaultMemoryBits, int additionalIterations = 0)
        {
            if (memoryBits < PasswordHasher.MinMemoryBits || memoryBits > PasswordHasher.MaxMemoryBits)
                throw new MemoryBitsOutOfRangeException(memoryBits);

            _systemSalt = "AXHwyuIHKoC1jeOgl0Di2f3s9hSDpjOaVP8xD7X6bVu" + (systemSalt ?? "");

            int fillBlocks = (1 << (memoryBits - MULTIPLIER_BITS - PasswordHasher.DigestBits));

            _fillAmount = fillBlocks * PasswordHasher.DigestSize;

	        _mixingIterations = fillBlocks * 2 + additionalIterations;  /* # of times we call crypto_hash_sha512 */
	        _memoryBlocks = fillBlocks * MULTIPLIER;

            _hashArray = new byte[MemoryUsage + PasswordHasher.DigestSize]; /* add one because we'll store the running hash there */
        }

 
        public string Hash(string password, string userSalt)
        {
            using (SHA512 alg = SHA512.Create())
            {
            	// _hashArraySize is always a power of 2
                int bitmask = _memoryBlocks - 1;

                // we have a single running hash, but then we combine it with "randomly"-selected cells from the array
                var combinedHash = new byte[(MULTIPLIER + 1) * PasswordHasher.DigestSize];  /* add one because we'll store the running hash there */

#if DEBUG
                _hashes = new List<string>();
                _visitCounts = new int[_memoryBlocks];
                _hashesPerCell = new List<string>[_memoryBlocks];
                _hashToCells = new Dictionary<string, int[]>();

                for (int i = 0; i < _hashesPerCell.Length; i++ )
                    _hashesPerCell[i] = new List<string>();
#endif

                byte[] hash = new byte[PasswordHasher.DigestSize];

                var pbkdf2 = new PBKDF2<HMACSHA512>(Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(_systemSalt + userSalt ?? ""), 1);
                var bytes = pbkdf2.GetBytes(_fillAmount + PasswordHasher.DigestSize);
 
                int blockStart = 0;
                int[] blockStarts = new int[MULTIPLIER];

                /* initialize the running hash to what comes out of PBKDF2 after the hash_array is filled */
                Buffer.BlockCopy(bytes, _fillAmount, hash, 0, PasswordHasher.DigestSize);

                for (var i = 0; i < MULTIPLIER; i++)
                {
                    Buffer.BlockCopy(bytes, 0, _hashArray, blockStart, _fillAmount);
                    blockStart += _fillAmount;
                }

#if DEBUG
                _originalArray = new byte[_hashArray.Length];
                Buffer.BlockCopy(_hashArray, 0, _originalArray, 0, _hashArray.Length);
#endif

				// now "randomly mix up" the hash array
                for (int i = 0; i < _mixingIterations; i++)
                {
#if DEBUG
                    AddHash(hash);
#endif
                    int combinedHashEnd = PasswordHasher.DigestSize;

                	// combine the running hash with...
                    Buffer.BlockCopy(hash, 0, combinedHash, 0, PasswordHasher.DigestSize);
                    
 
					// ..."randomly"-selected cells in the hash array
                    for (int m = 0; m < MULTIPLIER; m++ )
                    {
                    	// create a random int from bytes in the running hash and interpret the int as which cell to get a hash from.
                    	// Since hashes are 64 bytes long and ints are 4 bytes, we can only get 16 random indexes from the hash,
                    	// which is why _multiplier is limited to 16. 
                        int nextIndex = (hash[m * 4] + (hash[m * 4 + 1] << 8) + (hash[m * 4 + 2] << 16) +
                            (hash[m * 4 + 3] << 24)) & bitmask;
 
						// add that selected hash to the combined hash
                        blockStarts[m] = blockStart = nextIndex * PasswordHasher.DigestSize;
                        Buffer.BlockCopy(_hashArray, blockStart, combinedHash, combinedHashEnd, PasswordHasher.DigestSize);
                        combinedHashEnd += PasswordHasher.DigestSize;
#if DEBUG
                        _visitCounts[nextIndex]++;
#endif
                    }
 
					// update the running hash
                    hash = alg.ComputeHash(combinedHash);

#if DEBUG
                    var base64hash = Convert.ToBase64String(hash);
                    _hashToCells[base64hash] = new int[MULTIPLIER];
#endif

                    for (int m = 0; m < MULTIPLIER; m++)
                    {
                        blockStart = blockStarts[m];
                        // xor the selected hash with the running hash so that the hash array is constantly being modified
                        for (int b = 0; b < PasswordHasher.DigestSize; b++)
                            _hashArray[blockStart + b] ^= hash[b];
#if DEBUG
                        int hashIndex = blockStart / PasswordHasher.DigestSize;
                        _hashesPerCell[hashIndex].Add(base64hash);
                        _hashToCells[base64hash][m] = hashIndex;
#endif
                    }
                }
 
                return Convert.ToBase64String(alg.ComputeHash(_hashArray, 0, MemoryUsage));
            }
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

#if DEBUG
        private void AddHash(byte[] hash)
        {
            string base64hash = Convert.ToBase64String(hash);
            _hashes.Add(base64hash);

            if (_hashes.IndexOf(base64hash) != _hashes.Count - 1)
                throw new Exception("Duplicate hash at i=" + (_hashes.Count - 1));
        }
#endif
    }
}
