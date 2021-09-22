﻿// Copyright 2021 Nathaniel Aquino, All rights reserved.
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

        private byte[] FNK = new byte[128];

        private string path;

        private readonly byte FNKPad = 0xAA;

        private bool pathFlag = false;
        private int filePos;
        private readonly int readCount = 448;

        public enum InitType
        {
            file,
            text,
            bytes
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
        /// Returns a 1024 byte hash using ACH-1. Parameter input must be a string or a byte[].
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] ComputeHash(object input)
        { return ComputeHash_(input); }

        /// <summary>
        /// Returns a 1024 byte hash using ACH-1. Parameter input must be a string or a byte[]. Parameter FNK must be 128 bytes in length.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] ComputeHash(object input, byte[] FNK) // for actual input, use this.input, TODO: add overloads.
        { return ComputeHash_(input, FNK); }

        private byte[] ComputeHash_(object input, byte[] FNKO = null)
        {
            if (computeSetupFlag) // setup
            {
                // type matching
                var match = TypeMatch(input);
                if (!match.success)
                    throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");
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

                // generate FNK
                bool FNKS = false;
                if (FNKO == null) // case of no override
                {
                    FNKS = GetFNK(input, out byte[] GENFNK);
                    if (!FNKS)
                        throw new Exception("FNK Could not be generated");
                    FNK = GENFNK;
                    GENFNK = null;
                }

                
                computeSetupFlag = false; // FO Bool for FNK generation
            }

            // major compute loop
            bool computeFlag = true;
            int iter = 1;
            while (computeFlag)
            {
                Console.WriteLine($"Iteration: {iter}");
                computeFlag = false;

                // seq byteread
                this.input = SeqBR(input, filePos, readCount, out int readBytes);
                if (!(readBytes < readCount)) // final block
                    computeFlag = true;
                Console.WriteLine($"Read: {readBytes}");
                foreach (byte byt in this.input)
                    Console.Write(byt.ToString("X"));
                Console.WriteLine();
                iter++;
            }


            // clear vars
            Clear();
            return output;
        }

        #endregion

        #region methods and funcs

        private (bool success, Type type) TypeMatch(object input)
        {
            System.Type inputType = input.GetType();
            if (input == null)
                return (false, Type.notFound);
            if (inputType != typeof(string) && inputType != typeof(byte[]))
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

        /// <summary>
        /// Override the InitType of the current instance if ACH1.
        /// </summary>
        /// <param name="type"></param>
        public void OverrideMode(InitType type) => initType = type;

        /// <summary>
        /// Returns a 128 byte File Name Key. Parameter input must be a string or a byte[].
        /// </summary>
        /// <param name="input"></param>
        /// <param name="FNK"></param>
        /// <returns></returns>
        public bool GetFNK(object input, out byte[] FNK) // I am thinking about uprading all of the inittypes to work like InitType.file, but for now I am leaving it like this
        {
            System.Type typ = input.GetType();
            string path = "";
            if (typ == typeof(string))
                path = (string)input;
            else if (typ == typeof(byte[]))
                path = Encoding.ASCII.GetString((byte[])input);
            else
                throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");

            string fileName = path.Split('\\')[path.Split('\\').Length - 1].Split('.')[0];
            byte[] byteNameB1 = new byte[64];
            byte[] byteNameB2 = new byte[byteNameB1.Length];
            byte[] FNKOTPPad;
            int r;
            byte[] pad = new byte[] { FNKPad };

            path = null;
            switch (initType)
            {
                #region InitType.file

                case InitType.file:
                    if (byteNameB1.Length < 64)
                    {
                        byteNameB1 = Encoding.ASCII.GetBytes(fileName);
                        r = 64 - byteNameB1.Length;
                        pad = CreatePadArray(FNKPad, r);
                        byteNameB1 = AddArray(byteNameB1, pad);
                        
                        pad = null;
                        r = 0;
                    }
                    else if (byteNameB1.Length != 64)
                    {
                        byteNameB1 = Encoding.ASCII.GetBytes(fileName);
                        int fullBlocks = byteNameB1.Length / 64;
                        int seek = 64 * fullBlocks;
                        byte[] bnr = FCArray(byteNameB1, seek, 64 - (((fullBlocks + 1) * 64) - byteNameB1.Length));

                        byte[][] bnb1sbs = new byte[fullBlocks][];
                        for (int i = 0; i <= (fullBlocks - 1); i++)
                            bnb1sbs[i] = FCArray(byteNameB1, (i * 64), 64);

                        byteNameB1 = bnb1sbs[0];
                        foreach (byte[] subblock in bnb1sbs)
                        {
                            bool s1fo = true;
                            if (!s1fo)
                                byteNameB1 = OTPArray(byteNameB1, subblock);
                            else
                                s1fo = false;
                        }

                        bnr = null;
                        seek = 0;
                        fullBlocks = 0;
                        bnb1sbs = null;
                    }
                    FNKOTPPad = CreatePadArray(FNKPad, 64);
                    byteNameB2 = OTPArray(byteNameB1, FNKOTPPad);
                    FNK = AddArray(byteNameB1, byteNameB2);
                    return true;

                    #endregion

                #region InitType.text

                case InitType.text:
                    byteNameB1 = new byte[64];
                    byteNameB2 = new byte[byteNameB1.Length];

                    try
                    { byteNameB1 = Encoding.ASCII.GetBytes((string)input, 0, 64); }
                    catch (ArgumentOutOfRangeException u)
                    { byteNameB1 = Encoding.ASCII.GetBytes((string)input, 0, input.ToString().ToCharArray().Length); }
                    catch (Exception ex) { Console.WriteLine($"Unexcpected exception. {ex}"); }
                    if (byteNameB1.Length < 64)
                    {
                        pad = CreatePadArray(FNKPad, (64 - byteNameB1.Length));
                        byteNameB1 = AddArray(byteNameB1, pad);
                    }

                    pad = null;

                    FNKOTPPad = CreatePadArray(FNKPad, 64);
                    byteNameB2 = OTPArray(byteNameB1, FNKOTPPad);
                    FNK = AddArray(byteNameB1, byteNameB2);
                    return true;

                    #endregion

                #region InitType.bytes
                case InitType.bytes:
                    byteNameB1 = new byte[64];
                    byteNameB2 = new byte[byteNameB1.Length];

                    try
                    { byteNameB1 = FCArray((byte[])input, 0, 64);
                    } catch (ArgumentException u)
                    { byteNameB1 = FCArray((byte[])input, 0, ((byte[])input).Length); }
                    if (byteNameB1.Length < 64)
                    {
                        pad = CreatePadArray(FNKPad, (64 - byteNameB1.Length));
                        byteNameB1 = AddArray(byteNameB1, pad);
                    }

                    pad = null;

                    FNKOTPPad = CreatePadArray(FNKPad, 64);
                    byteNameB2 = OTPArray(byteNameB1, FNKOTPPad);
                    FNK = AddArray(byteNameB1, byteNameB2);
                    return true;
                    #endregion
            }

            FNK = null; return false;
        }

        public byte[] SeqBR(object i, int s, int c, out int r) // sequential bytereader
        {
            byte[] o = new byte[c];
            r = 0;
            // switch for init type
            switch (initType)
            {
                case InitType.file:
                    using (FileStream fs = new FileStream((string)i, FileMode.Open))
                        r = fs.Read(o, s, c);
                    filePos += r;
                        break;
                case InitType.text:
                    ;
                    break;
                case InitType.bytes:
                    ;
                    break;
            }
            return o;
        }

        #region Array Funcs

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

        #endregion
    }
}
