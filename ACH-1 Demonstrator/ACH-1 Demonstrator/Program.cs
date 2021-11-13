using System;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using System.IO;

namespace ACH_1_Demonstrator
{
    class Program
    {
        static void Main(string[] args)
        {
            #region main program

            try
            {
                var timer = new Stopwatch();
                switch (args[0])
                {
                    case "-testFNKpath":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.file))
                        {
                            Console.WriteLine();
                            if (ach1.GetFNK(args[1], out byte[] test))
                                foreach (byte byt in test)
                                    Console.Write(byt.ToString("X"));
                            else
                                Console.WriteLine("\nEpic Fail!");
                            Console.WriteLine($"\nFNK Length: {test.Length}");
                        }

                        break;
                    case "-testFNKtext":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.text))
                        {
                            Console.WriteLine();
                            if (ach1.GetFNK(args[1], out byte[] FNK))
                                foreach (byte byt in FNK)
                                    Console.Write(byt.ToString("X"));
                            else
                               Console.WriteLine("Epic Fail!");
                            Console.WriteLine($"\nFNK Length: {FNK.Length}");
                        }
                        break;
                    case "-testFNKFilestream":
                        using (System.IO.FileStream fs = new System.IO.FileStream(args[1], System.IO.FileMode.Open))
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                        {
                            Console.WriteLine();
                            if (ach1.GetFNK(fs, out byte[] FNK))
                                foreach (byte byt in FNK)
                                    Console.Write(byt.ToString("X"));
                            else
                                Console.WriteLine("Epic Fail!");
                            Console.WriteLine($"\nFNK Length: {FNK.Length}");
                        }
                            break;
                    case "-testFNKbyte[]":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.bytes))
                        {
                            Console.WriteLine();
                            byte[] in_ = Encoding.ASCII.GetBytes(args[1]);
                            if (ach1.GetFNK(in_, out byte[] FNK))
                                foreach (byte byt in FNK)
                                    Console.Write(byt.ToString("X"));
                            else
                                Console.WriteLine("Epic Fail!");
                            Console.WriteLine($"\nFNK Length: {FNK.Length}");
                        }
                        break;
                    case "-file":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.file))
                        {
                            timer.Start();
                            var res = ach1.ComputeHash(args[1]);
                            timer.Stop();
                            foreach (var byt in res)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nHash length: {res.Length}. Input Length: {args[1].Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                        }
                        break;
                    case "-text":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.text))
                        {
                            timer.Start();
                            var res = ach1.ComputeHash(args[1]);
                            timer.Stop();
                            foreach (var byt in res)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nHash length: {res.Length}. Input Length: {args[1].Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                        }
                        break;
                    case "-fileStream":
                        using (FileStream fs = new FileStream(args[1], System.IO.FileMode.Open))
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                        {
                            timer.Start();
                            var res = ach1.ComputeHash(fs);
                            timer.Stop();
                            foreach (byte byt in res)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nHash length: {res.Length}. Input Length: {args[1].Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                        }
                        break;
                    case "-testFNKFileStream":
                        using (FileStream fs = new FileStream(args[1], System.IO.FileMode.Open))
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                        {
                            ach1.GetFNK(fs, out byte[] FNK);
                            foreach (byte byt in FNK)
                                Console.WriteLine(byt.ToString("X"));
                            Console.WriteLine($"\nFNK Length: {FNK.Length}");
                        }
                        break;
                    case "-memoryStream":
                        using (MemoryStream ms = new MemoryStream())
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                        {
                            var test = new byte[] { 0x65, 0x23, 0x4A, 0xFF, 0xFF, 0xD6, 0x63, 0x11, 0x6F, 0xC9, 0x54, 0xD5 };
                            ms.Write(test);
                            timer.Start();
                            var res = ach1.ComputeHash(ms);
                            timer.Stop();
                            foreach (var byt in res)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nHash length: {res.Length}. Input Length: {test.Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                        }
                        break;
                    case "-testFNKMemoryStream":
                        using (MemoryStream ms = new MemoryStream())
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                        {
                            ms.Write(new byte[] { 0x65, 0x23, 0x4A, 0xFF, 0xFF, 0xD6, 0x63, 0x11, 0x6F, 0xC9, 0x54, 0xD5 });
                            ach1.GetFNK(ms, out byte[] FNK);
                            foreach (var byt in FNK)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nFNK Length: {FNK.Length}");
                        }
                        break;
                    case "-textfromfile":
                        ; // read text, parse as byte[] and feed into ACH1
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.text))
                            ;
                        break;
                    case "-bytes":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.bytes))
                        {
                            byte[] in_ = new byte[] { 0x65, 0x23, 0x4A, 0xFF, 0xFF, 0xD6, 0x63, 0x11, 0x6F, 0xC9, 0x54, 0xD5 };
                            foreach (var byt in in_)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine();
                            timer.Start();
                            var res = ach1.ComputeHash(in_);
                            timer.Stop();
                            foreach (var byt in res)
                                Console.Write(byt.ToString("X"));
                            Console.WriteLine($"\nHash length: {res.Length}. Input Length: {in_.Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                        }
                        break;
                    case "-sha": // just looking at how the function is commented on.
                        using (SHA1 sha1 = SHA1.Create())
                            sha1.ComputeHash(new byte[] { 0xAA, 0xBB });
                        break;
                    case "-testSpike":

                        break;

                    #region stream testing

                    case "-streamStressTest":
                        int streamStressTestSeed = 456765478;
                        var random = new Random(streamStressTestSeed);
                        for (int i = 1; i <= 8; i++)
                        {
                            Console.WriteLine($"Generating random data for order of magnitude {MathF.Pow(10, i)} ({i}).");
                            int mag = (int)MathF.Pow(10, i);
                            byte[] data = new byte[mag];
                            for (int a = 0; a <= mag - 1; a++)
                                data[a] = (byte)(random.Next() * 1000 % 255);
                            using (MemoryStream ms = new MemoryStream())
                            using (ACH1 ach1 = new ACH1(ACH1.InitType.stream))
                            {
                                ms.Write(data, 0, data.Length);
                                Console.WriteLine("Hashing...");
                                timer.Start();
                                var res = ach1.ComputeHash(ms);
                                timer.Stop();
                                foreach (var byt in res)
                                    Console.Write(byt.ToString("X"));
                                Console.WriteLine($"\nHash length: {res.Length}. Input Length: {data.Length} bytes | Elapsed time: {timer.Elapsed.ToString(@"m\:ss\.fff")}");
                            }
                        }

                        break;

                        #endregion
                }
            }
            catch (Exception ex)
            { Console.WriteLine(ex.ToString()); }

            #endregion


            #region test programs



            #endregion
        }
    }
}
