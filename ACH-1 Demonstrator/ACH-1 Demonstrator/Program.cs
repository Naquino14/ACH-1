using System;
using System.IO;
using System.Text;

namespace ACH_1_Demonstrator
{
    class Program
    {
        static void Main(string[] args)
        {
            #region main program

            try
            {
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
                            ;
                        break;
                    case "-text":
                        ;
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.text))
                            ; // parse args[1] as byte[] and feed into ACH1
                        break;
                    case "-textfromfile":
                        ; // read text, parse as byte[] and feed into ACH1
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.text))
                            ;
                        break;
                    case "-bytes":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.bytes))
                            ; // parse args[1] as byte[] and 
                        break;

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
