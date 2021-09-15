// Copyright 2021 Nathaniel Aquino, All rights reserved.
// Aquino Cryptographic Hash version 1
using System;
using System.IO;
using System.Text;

namespace ACH_1_Demonstrator
{
    public class ACH1 : IDisposable
    {
        #region variables

        public InitType initType;
        private bool disposedValue;

        private bool computeSetupFlag = true;

        private byte[] prevBlock;
        private byte[] block;

        private byte[] output = new byte[1024];
        private byte[] input;

        private string path;

        private readonly byte FNKPad = 0xAA;

        public enum InitType
        {
            file,
            text
        }
        private enum Type
        {
            tString,
            tByte,
            notFound
        }

        #endregion

        #region initialization and disposal methods

        public ACH1(InitType initType) => this.initType = initType;


        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
                if (disposing)
                {
                    prevBlock = null;
                    block = null;
                    output = null;
                    input = null;
                    path = null;

                    disposedValue = true;
                }
        }

        public void Dispose() => Dispose(true);

        #endregion

        #region main function

        /// <summary>
        /// Returns a 1024 bit hash using ACH-1. Parameter input must be a string or a byte[].
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] ComputeHash(object input) // for actual input, use this.input
        {
            if (computeSetupFlag)
            {
                // reset vars
                Clear();

                // type matching
                var match = TypeMatch(input);
                if (!match.success)
                    throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");
                bool pathFlag = false;
                switch (match.type)
                {
                    case Type.tByte:
                        this.input = (byte[])input;
                        break;
                    case Type.tString:
                        path = (string)input;
                        pathFlag = true;
                        break;
                    case Type.notFound: break;
                }
                if (!GetFNK(input, out byte[] FNK))
                    throw new Exception("FNK Could not be generated");
                if (pathFlag)
                    ; // do stuff i think
                
            }
            return output;
        }

        #endregion

        #region methods and funcs

        private (bool success, Type type) TypeMatch(object input)
        {
            System.Type inputType = input.GetType();
            if (input == null)
                return (false, Type.notFound);
            if (inputType != typeof(string) || inputType != typeof(byte[]))
                return (false, Type.notFound);
            if (inputType == typeof(string))
                return (true, Type.tString);
            else
                return (true, Type.tByte);
        }

        /// <summary>
        /// Forcefully clears certain variables in ACH-1. 
        /// </summary>
        public void Clear()
        {
            output = null;
            input = null;
            path = null;
        }

        public bool GetFNK(object input, out byte[] FNK)
        {
            switch (initType)
            {
                case InitType.file:
                    string path = (string)input;
                    string fileName = path.Split('\\')[path.Split('\\').Length - 1].Split('.')[0];
                    byte[] byteNameB1 = Encoding.ASCII.GetBytes(fileName);
                    byte[] byteNameB2 = new byte[byteNameB1.Length];
                    byte[] FNKOTPPad;
                    int r;
                    byte[] pad = new byte[] { FNKPad };
                    if (byteNameB1.Length < 64)
                    {
                        r = 64 - byteNameB1.Length;
                        pad = CreatePadArray(FNKPad, r);
                        byteNameB1 = AddArray(byteNameB1, pad);

                        pad = null;
                        r = 0;
                    }
                    else if (byteNameB1.Length != 64) // greater than 64
                    {
                        // determine how many blocks to create
                        int fullBlocks = byteNameB1.Length / 64;
                        // find a byte to seek at
                        int seek = 64 * fullBlocks;
                        // grab end of block
                        /// to do that, get the amount of blocks, ex: 2 and add 1, this gets a certain multiple of 64 that is larger than the length of the final segment
                        /// ex 2: 3 * 64 = 192
                        /// then get the difference. suppose our byte name block is 163 bytes, ex 3: 192 - 163 = 29 residual bytes
                        /// to get the count of how many bytes to copy after the seek simply subtract 64 from that number, 64 - 29 = 35 bytes
                        /// we can then verify this. our block is 163 bytes, 64 * 2 for two full blocks is 128, plus 35 is 163
                        /// then use fast copy array to copy these bytes to a new array, by seeking at the end of subblocks 1 and 2 in the bytename block
                        /// (which are both 64 bytes each, so you can get the exact number by dividing the length of the byteName block by 64 and multiplying it by 64)
                        /// ex: 163 bytes yields 2 full blocks, so seek at 64 * 2 = 128
                        /// once this is done fast copy the array to itself, but only up to the seek number * 64 (128 in this case, again.)

                        byte[] byteNameResidue = FCArray(byteNameB1, seek, 64 - (((fullBlocks + 1) * 64) - byteNameB1.Length));

                        // otp merge multiple blocks
                        // create 2d array for subblocks of byte name b1
                        byte[][] bnb1sbs = new byte[fullBlocks][];
                        // iterate over full subblocks of bnb1
                        for (int i = 0; i <= (fullBlocks - 1); i++)
                            bnb1sbs[i] = FCArray(byteNameB1, (i * 64), 64);

                        //// test
                        //Console.WriteLine(fullBlocks);
                        //Console.WriteLine($"BNB1 untrimmed length: {byteNameB1.Length}");
                        //PrintArray(byteNameB1, "BNB1");
                        //Console.WriteLine($"BNB1SB1 untrimmed length: {bnb1sbs[0].Length}");
                        //PrintArray(bnb1sbs[0], "BNB1SB1");
                        //Console.WriteLine($"BNB1SB2 length: {bnb1sbs[1].Length}");
                        //PrintArray(bnb1sbs[1], "BNB1SB2");
                        //Console.WriteLine($"BNB1SB3 length: {bnb1sbs[2].Length}");
                        //PrintArray(bnb1sbs[2], "BNB1SB3");
                        //Console.WriteLine($"BNBS1SB4 length: {bnb1sbs[3].Length}");
                        //PrintArray(bnb1sbs[3], "BNB1SB4");
                        //Console.WriteLine($"BNB1Residue Length: {byteNameResidue.Length}");
                        //PrintArray(byteNameResidue, "Residue");
                        //Console.WriteLine($"Final length: {(bnb1sbs[0].Length + bnb1sbs[1].Length + bnb1sbs[2].Length + bnb1sbs[3].Length + byteNameResidue.Length)}");
                        // clear vars
                        byteNameResidue = null;
                        seek = 0;
                        fullBlocks = 0;
                    }
                    // create a pad for the second subblock to be otped by
                    FNKOTPPad = CreatePadArray(FNKPad, 64);
                    // otp merge pad and second subblock
                    //byteNameB2 = OTPArray(byteNameB1, FNKOTPPad);
                    // regular merge both subblocks
                    FNK = AddArray(byteNameB1, byteNameB2);
                    //Console.WriteLine($"File Name Key size: {FNK.Length}");
                    //Console.Write("File Name Key: ");
                    return true;
                case InitType.text:
                    // TODO: uhhhh
                    break;
            }

            FNK = null; return false;
        }

        private byte[] FCArray(byte[] input, int s, int c)
        {
            byte[] result = new byte[c];
            Array.Copy(input, s, result, 0, c);
            return result;
        }

        private byte[] AddArray(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            a.CopyTo(result, 0);
            b.CopyTo(result, a.Length);
            return result;
        }

        private byte[] AddByteToArray(byte[] a, byte b)
        {
            byte[] result = new byte[a.Length + 1];
            a.CopyTo(result, 0);
            result[result.Length - 1] = b;
            return result;
        }

        private byte[] Check64ByteFit(byte[] input)
        {
            if (input.Length > 64)
            { FCArray(input, 0, 64); return input; }
            else
                return input;
        }

        private byte[] OTPArray (byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                result[i] = (byte)(input[i] ^ key[i]);
            return result;
        }

        private byte[] OTPFit (byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            byte[] fit = new byte[key.Length];
            for (int i = 0; i <= key.Length; i++)
                fit[i] = (byte)(input[i] ^ key[i]);
            input.CopyTo(result, 0);
            fit.CopyTo(result, 0);
            return result;
        }

        void PrintArray(byte[] array, string name = "")
        {
            if (name != "")
                Console.Write($"{name}: ");
            foreach (byte byt in array)
                Console.Write(byt.ToString("X"));
            Console.WriteLine();
        }
        
        private byte[] CreatePadArray(byte b, int s)
        {
            byte[] result = new byte[s];
            for (int i = 0; i < s; i++)
                result[i] = b;
            return result;
        }
        #endregion
    }
}
