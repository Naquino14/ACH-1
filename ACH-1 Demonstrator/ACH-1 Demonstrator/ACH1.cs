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
                    byte[] byteName = Encoding.ASCII.GetBytes(fileName);
                    Console.WriteLine(byteName.Length);
                    if (byteName.Length < 64)
                    {
                        #region padding
                        int r = 64 - byteName.Length;
                        byte[] pad = new byte[] { FNKPad };
                        for (int i = 1; i < r; i++)
                            pad = AddByteToArray(pad, FNKPad);
                        byteName = AddArray(byteName, pad);
                        Console.WriteLine(byteName.Length);
                        PrintArray(byteName);
                        byteName = AddArray(byteName, pad);
                        #endregion

                        pad = null;
                        r = 0;

                        #region OTP
                        byte[] bytenameOTP = OTPArray(byteName, byteName);
                        PrintArray(bytenameOTP);
                        Console.WriteLine(bytenameOTP.Length);
                        #endregion
                    }
                    else
                    {

                    }

                    //
                    FNK = null;
                    return true;
                case InitType.text:
                    // TODO: uhhhh
                    break;
            }

            FNK = null; return false;
        }

        private byte[] FCrray(byte[] input, int s, int c)
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
            { FCrray(input, 0, 64); return input; }
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

        void PrintArray(byte[] array)
        {
            foreach (byte byt in array)
                Console.Write(byt.ToString("X"));
            Console.WriteLine();
        }
        #endregion
    }
}
