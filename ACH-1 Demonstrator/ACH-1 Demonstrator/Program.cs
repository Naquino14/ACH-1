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
                    case "-testFNK":
                        using (ACH1 ach1 = new ACH1(ACH1.InitType.file))
                        {
                            if (ach1.GetFNK(args[1], out byte[] test))
                                foreach (byte byt in test)
                                    /*Console.Write(byt.ToString("X"));*/
                                    ;
                            else
                                Console.WriteLine("Epic Fail!");
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
