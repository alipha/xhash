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
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace XHash.Test
{
    public class Program
    {
#if DEBUG
        struct HashTreeInfo
        {
            public int depth;
            public long count;
            public long iterations;

            public override string ToString() { return String.Format("{0}\t{1}\t{2}", depth, count, iterations); }
        }

        private static IDictionary<string, HashTreeInfo> _info = new Dictionary<string, HashTreeInfo>();
        private static IList<string> _mixingHashes;
        private static IDictionary<string, string> _prevHash = new Dictionary<string, string>();
#endif

        public static void Main(string[] args)
        {
            int iterations = 12500;
            int multiplier = 4;

            var chasher = new PasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=", iterations, multiplier);

            var startTime = DateTime.UtcNow;
            string hash = chasher.Hash("foo1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            Console.WriteLine((DateTime.UtcNow - startTime).TotalMilliseconds);
            Console.WriteLine(hash);
            Console.WriteLine(chasher.MemoryUsage);

            var hasher = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=", iterations, multiplier);

            startTime = DateTime.UtcNow;
            hash = hasher.Hash("foo1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            Console.WriteLine((DateTime.UtcNow - startTime).TotalMilliseconds);
            Console.WriteLine(hash);
            Console.WriteLine(hasher.MemoryUsage);
#if DEBUG
            /* cell frequency */
            if (!Directory.Exists("stats"))
                Directory.CreateDirectory("stats");

            CellFrequency(String.Format("cellfreq-{0}-{1}.txt", iterations, multiplier), hasher.__hashArray);


            /* xored cell frequency */
            byte[] xored = new byte[hasher.MemoryUsage];

            for (int i = 0; i < xored.Length; i++)
                xored[i] = (byte)(hasher.__hashArray[i] ^ hasher._originalArray[i]);

            Console.WriteLine("0 xor bytes: " + xored.Count(x => x == 0));

            CellFrequency(String.Format("xor-cellfreq-{0}-{1}.txt", iterations, multiplier), xored);


            /* visit counts */
            var chars = "0123456789abcdefghijklmnopqrstuvwxyz".ToCharArray();
            System.IO.File.WriteAllText(String.Format(@"stats\hash-{0}-{1}.txt", iterations, multiplier), String.Join("", hasher._visitCounts.Select(v => chars[v])));


            /* depth, count, iterations */
            int hashArraySize = hasher.__hashArraySize / (1 << multiplier);
            _mixingHashes = hasher._hashes.Skip(hashArraySize + 1).ToList();

            string prevHash = hasher._hashes[hashArraySize];

            _info[prevHash] = new HashTreeInfo 
            {
                depth = 1,
                count = 0,
                iterations = 1
            };

            foreach(string nextHash in _mixingHashes)
            {
                _prevHash[nextHash] = prevHash;
                prevHash = nextHash;
            }

            var depths = _mixingHashes.Select(h => GetTreeInfo(hasher, h).ToString());
            System.IO.File.WriteAllLines(String.Format(@"stats\depths-{0}-{1}.txt", iterations, multiplier), depths);
#endif
            Console.ReadLine();
        }


        private static void Test()
        {
            var hasher1 = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=");
            var hasher2 = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oafUy4N2iEHmL2NkIw=");
            var hasher3 = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=", 17001);
            //Console.WriteLine(PasswordHasher.GenerateSalt());

            var startTime = DateTime.UtcNow;
            var result1a = hasher1.Hash("password1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            Console.WriteLine((DateTime.UtcNow - startTime).TotalMilliseconds);

            var result1b = hasher1.Hash("password1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            var result1c = hasher1.Hash("password1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCq");
            var result1d = hasher1.Hash("password2", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            var result2  = hasher2.Hash("password1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");
            var result3  = hasher3.Hash("password1", "NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp");

            Console.WriteLine(result1a);
            Console.WriteLine(result1b);
            Console.WriteLine();
            Console.WriteLine(result1a);
            Console.WriteLine(result1c);
            Console.WriteLine();
            Console.WriteLine(result1a);
            Console.WriteLine(result1d);
            Console.WriteLine();
            Console.WriteLine(result1a);
            Console.WriteLine(result2);
            Console.WriteLine();
            Console.WriteLine(result1a);
            Console.WriteLine(result3);
            Console.WriteLine();

        }
        
        private static void MS_Pbkdf2_Timing()
        {
            var startTime = DateTime.UtcNow;
            Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes("foo1", Encoding.ASCII.GetBytes("NyfLZ6RJXWE1aHrrM5JRefMlipdBV0bCp"), 1);
            byte[] bytes = k1.GetBytes(262144);
            byte[] total = new byte[262144 * 16];
            for (int i = 0; i < 16; ++i)
                Buffer.BlockCopy(bytes, 0, total, i * 262144, 262144);
            Console.WriteLine((DateTime.UtcNow - startTime).TotalMilliseconds);
            Console.ReadLine();
        }

#if DEBUG
        private static void VisitCounts()
        {
            var chars = "0123456789abcdefghijklmnopqrstuvwxyz".ToCharArray();

            var hasher = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=", 12288, 4);

            DateTime startTime = DateTime.UtcNow;
            hasher.Hash("foo", "");
            Console.WriteLine((DateTime.UtcNow - startTime).TotalMilliseconds);
            
            System.IO.File.WriteAllText(@"stats\hash-12288-16.txt", String.Join("", hasher._visitCounts.Select(v => chars[v])));
        }

        private static void ByteFrequency()
        {
            var hasher = new TestPasswordHasher("Qq48KGoFOXbZcBXDHZuqyjTP5oBfUy4N2iEHmL2NkIw=", 65536 + 32768, 4);
            Console.WriteLine(hasher.MemoryUsage);
            //Console.ReadLine();

            using (var rng = new RNGCryptoServiceProvider())
            {
                var randomBytes = new byte[4096 * 16 * 512 / 8];
                rng.GetBytes(randomBytes);
                ByteFrequency("randomfreq.txt", randomBytes);
                ByteFrequency("hashfreq.txt", hasher.__hashArray);
            }
        }

        private static void ByteFrequency(string filename, byte[] array)
        {
            IDictionary<int, int> bytes = new Dictionary<int, int>();

            foreach(var b in array) 
            {
                if (bytes.ContainsKey(b))
                    bytes[b]++;
                else
                    bytes[b] = 1;
            }

            System.IO.File.WriteAllLines(@"stats\" + filename, bytes.Select(b => b.Value.ToString())); //bytes.Select(b => b.Key + " = " + b.Value));
        }

        private static void CellFrequency(string filename, byte[] array)
        {
            IDictionary<string, List<int>> cellLocations = new Dictionary<string, List<int>>();

            for(int i = 0; i < array.Length; i += 64)
            {
                string hash = Convert.ToBase64String(array, i, 64);

                if (!cellLocations.ContainsKey(hash))
                    cellLocations[hash] = new List<int>();

                //if (cellLocations[hash].Any() && cellLocations[hash].First() / 16 != i / (64*16))
                //    throw new Exception(hash + " is repeated at " + cellLocations[hash].First() + " and " + i / 64);

                cellLocations[hash].Add(i / 64);
            }

            Console.WriteLine("Distinct hashes: " + cellLocations.Count);

            var locations = cellLocations.Where(c => c.Value.Count > 1).Select(c => String.Format("{0} = {1}",
                c.Key, String.Join(", ", c.Value.Select(i => i.ToString("X")))));

            System.IO.File.WriteAllLines(@"stats\" + filename, locations);
        }

        private static HashTreeInfo GetTreeInfo(TestPasswordHasher hasher, string hash)
        {
            if (_info.ContainsKey(hash))
                return _info[hash];

            HashTreeInfo info = new HashTreeInfo { depth = 0, count = 0, iterations = _info[_prevHash[hash]].iterations + 1 };

            foreach (int index in hasher._hashToCells[hash])
            {
                IList<string> cellHashes = hasher._hashesPerCell[index];

                for (int i = 0; i < cellHashes.Count && cellHashes[i] != hash; i++ )
                {
                    HashTreeInfo childInfo = GetTreeInfo(hasher, cellHashes[i]);

                    if (childInfo.depth > info.depth)
                        info.depth = childInfo.depth;

                    info.count += childInfo.count + 1;
                    info.iterations += childInfo.iterations;
                }
            }

            info.depth++;
            _info[hash] = info;
            return info;
        }
#endif
    }
}
