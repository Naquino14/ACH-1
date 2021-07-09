using System;
using System.IO;

namespace ACH_1_Demonstrator
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                switch (args[0])
                {
                    case "-file":
                        using (ACH1 ach1 = new ACH1(ACH1.ACH1InitType.file))
                            ;
                        break;
                    case "-text":
                        ;
                        using (ACH1 ach1 = new ACH1(ACH1.ACH1InitType.text))
                            ; // parse args[1] as byte[] and feed into ACH1
                        break;
                    case "-textfromfile":
                        ; // read text, parse as byte[] and feed into ACH1
                        using (ACH1 ach1 = new ACH1(ACH1.ACH1InitType.text))
                            ;
                        break;

                }
            }
            catch (Exception ex)
            { Console.WriteLine(ex.ToString()); }
        }
    }
}
