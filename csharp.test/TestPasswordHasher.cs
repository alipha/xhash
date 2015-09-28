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
        private string _systemSalt;
        private int _iterations;
        private int _multiplier;
 
        private int _hashArraySize;
        private byte[] _hashArray;

        public int HashByteSize { get { return 64; } }

        public int MemoryUsage { get { return _hashArraySize * HashByteSize; } }

#if DEBUG
        public IList<string> _hashes;
        public int[] _visitCounts;
        public byte[] _originalArray;
        public byte[] __hashArray { get { return _hashArray; } }
        public int __hashArraySize { get { return _hashArraySize; } }
        public IDictionary<string, int[]> _hashToCells;
        public IList<string>[] _hashesPerCell;
#endif
 
        // memoryMultiplier has a range of [0, 4]
        // iterations * 2^memoryMultiplier < 2^24 (16 million)
        public TestPasswordHasher(string systemSalt = "", int iterations = 12288, int memoryMultiplier = 4)
        {
            if (iterations < 3) // 2)
                throw new IterationsOutOfRangeException(iterations);
            if (memoryMultiplier < 0 || memoryMultiplier > 4)
                throw new MemoryMultiplierOutOfRangeException(memoryMultiplier);


            _systemSalt = "AXHwyuIHKoC1jeOgl0Di2f3s9hSDpjOaVP8xD7X6bVu" + (systemSalt ?? "");
            _iterations = iterations;  // # of times we call SHA512.ComputeHash
            _multiplier = 1 << memoryMultiplier;
 
			// We want to pick an array size that's a power of two so that the "random" selection of the next cell is fast to perform
            _hashArraySize = 3; // 2;
 
            while (_hashArraySize <= _iterations)
                _hashArraySize *= 2;
 
            _hashArraySize &= _hashArraySize - 1;

			// Dividing by 4 guarantees that the number of iterations performed in the "random mixing up" step is at least as 
            // many as the # of cells (and potentionally up to 3 times as many)
            _hashArraySize /= 4;
            _hashArraySize *= _multiplier;
        }

 
        public string Hash(string password, string userSalt)
        {
            using (SHA512 alg = SHA512.Create())
            {
            	// _hashArraySize is always a power of 2
                int bitmask = _hashArraySize - 1;
                int hashSize = HashByteSize;	// in bytes
                int hashSubArrayLen = _hashArraySize / _multiplier * hashSize;
 
                // we have a single running hash, but then we combine it with "randomly"-selected cells from the array
                var combinedHash = new byte[(_multiplier + 1) * hashSize];  /* add one because we'll store the running hash there */

#if DEBUG
                _hashes = new List<string>();
                _visitCounts = new int[_hashArraySize];
                _hashesPerCell = new List<string>[_hashArraySize];
                _hashToCells = new Dictionary<string, int[]>();

                for (int i = 0; i < _hashesPerCell.Length; i++ )
                    _hashesPerCell[i] = new List<string>();
#endif

                if (_hashArray == null)
                    _hashArray = new byte[_hashArraySize * hashSize];
 
                byte[] hash = new byte[hashSize];

                var pbkdf2 = new PBKDF2<HMACSHA512>(Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(_systemSalt + userSalt), 1);
                var bytes = pbkdf2.GetBytes(hashSubArrayLen + hashSize);
 
                int blockStart = 0;
                int[] blockStarts = new int[_multiplier];

                /* initialize the running hash to what comes out of PBKDF2 after the hash_array is filled */
                Buffer.BlockCopy(bytes, hashSubArrayLen, hash, 0, hashSize);

                for (var i = 0; i < _multiplier; i++)
                {
                    Buffer.BlockCopy(bytes, 0, _hashArray, blockStart, hashSubArrayLen);
                    blockStart += hashSubArrayLen;
                }

#if DEBUG
                _originalArray = new byte[_hashArray.Length];
                Buffer.BlockCopy(_hashArray, 0, _originalArray, 0, _hashArray.Length);
#endif

				// now "randomly mix up" the hash array for the remaining iterations
                for (int i = _hashArraySize / _multiplier; i < _iterations; i++)
                {
#if DEBUG
                    AddHash(hash);
#endif
                    int combinedHashIndex = 0;

                	// combine the running hash with...
                    Buffer.BlockCopy(hash, 0, combinedHash, combinedHashIndex, hashSize);
                    
 
					// ..."randomly"-selected cells in the hash array
                    for (int m = 0; m < _multiplier; m++ )
                    {
                        combinedHashIndex += hashSize;

                    	// create a random int from bytes in the running hash and interpret the int as which cell to get a hash from.
                    	// Since hashes are 64 bytes long and ints are 4 bytes, we can only get 16 random indexes from the hash,
                    	// which is why _multiplier is limited to 16. 
                        // (We're actually only using 24 bits per int, since that is enough for now, but could expand to 32 bits)
                        int nextIndex = (hash[m * 4] + (hash[m * 4 + 1] << 8) + (hash[m * 4 + 2] << 16)) & bitmask;
 
						// add that selected hash to the combined hash
                        blockStarts[m] = blockStart = nextIndex * hashSize;
                        Buffer.BlockCopy(_hashArray, blockStart, combinedHash, combinedHashIndex, hashSize);

#if DEBUG
                        _visitCounts[nextIndex]++;
#endif
                    }
 
					// update the running hash
                    hash = alg.ComputeHash(combinedHash);

#if DEBUG
                    var base64hash = Convert.ToBase64String(hash);
                    _hashToCells[base64hash] = new int[_multiplier];
#endif

                    for (int m = 0; m < _multiplier; m++)
                    {
                        blockStart = blockStarts[m];
                        // xor the selected hash with the running hash so that the hash array is constantly being modified
                        for (int b = 0; b < hashSize; b++)
                            _hashArray[blockStart + b] ^= hash[b];
#if DEBUG
                        _hashesPerCell[blockStart / hashSize].Add(base64hash);
                        _hashToCells[base64hash][m] = blockStart / hashSize;
#endif
                    }
                }
 
                return Convert.ToBase64String(hash);
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
