// Copyright 2021 Nathaniel Aquino, All rights reserved.
// Aquino Cryptographic Hash version 1
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Runtime;

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

        private bool pathFlag = false;


        // constants
        private readonly byte FNKPad = 0xAA;
        private readonly byte JumpConstant = 0xFF;
        private readonly byte MainSubblockPad = 0x15;

        private readonly int brsIndex = 380; // block rotation sample index

        private readonly int readCount = 448;

        private readonly int spikeStrength = 4;

        public enum InitType
        {
            file,
            text,
            bytes,
            stream
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

                    disposedValue = true;
                }
        }

        public void Dispose() => Dispose(true);

        #endregion

        #region main function

        /// <summary>
        /// Computes the hash using ACH-1 for the specified input using the specified method in the constructor.
        /// </summary>
        /// <param name="input">Input data, or a path to a file, to be hashed using the generation method specified in the constructor.</param>
        /// <returns>A 1024 byte hash using ACH-1.</returns>
        public byte[] ComputeHash(object input)
        { return ComputeHash_(input); }

        /// <summary>
        /// Computes the hash using ACH-1 for the specified input using the specified method in the constructor.
        /// </summary>
        /// <param name="input">Input data, or a path to a file, to be hashed using the generation method specified in the constructor.</param>
        /// <param name="FNK">File Name Key override to be used instead of automatically generating one from the generation method specified in the constructor.</param>
        /// <returns>A 2024 byte hash using ACH-1.</returns>
        public byte[] ComputeHash(object input, byte[] FNK) // for actual input, use this.input, TODO: add overloads.
        { return ComputeHash_(input, FNK); }

        private byte[] ComputeHash_(object input, byte[] FNKO = null) // todo: i forgor datastreams :skull:
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
            int computationIteration = 0;
            int read;
            while (computeFlag)
            {
                Console.WriteLine($"Iteration: {computationIteration}");
                computeFlag = false;
                (int fullBlocks, int fileLength) seqBrInfo = (0, 0);

                if (pathFlag) // case of a file, get input
                {
                    // get next block
                    switch (initType)
                    {
                        case InitType.file:
                            // seq byteread
                            seqBrInfo = InitSeqBR(input);
                            read = SeqBR(input, computationIteration, out block);
                            computeFlag = !(read < readCount); // true if the computation isnt finished
                            break;
                        case InitType.bytes:
                            throw new NotImplementedException();
                            //break;
                        case InitType.text:
                            throw new NotImplementedException();
                            //break;
                    }
                    // check to see if padding for the main sublock is required
                    if (block.Length < 448)
                        block = AddArray(block, CreatePadArray(MainSubblockPad, 448 - block.Length));

                    // ciphered bytes formation
                    byte[] CBKey = new byte[448];
                    CBKey = AddArray(FNK, FNK);
                    CBKey = AddArray(CBKey, FNK);
                    // create a pad for the fnk, it should be 64 bytes.
                    byte[] CBFNKPad = CreatePadArray(FNKPad, 64);
                    CBKey = AddArray(CBKey, CBFNKPad);
                    // append ciphered bytes and fnk to current block
                    block = AddArray(block, OTPArray(block, CBKey));
                    block = AddArray(block, FNK);

                    #region seeding

                    int SC = GenerateSeedConstant(block, computationIteration);
                    Console.WriteLine($"Seed constant for round {computationIteration}: {SC}");

                    Console.WriteLine();
                    PrintArray(block, "State");
                    //Console.WriteLine($"Rotating {block[brsIndex]} right...");
                    //block = RotRight(block, block[brsIndex]);
                    //PrintArray(block, "Rotated state");
                    Console.WriteLine("Spiking...");
                    BlockSpike(block);
                    PrintArray(block, "Spiked state");
                    Console.WriteLine("Jumping...");
                    BlockJump(block);
                    PrintArray(block, "Jumped state");
                }
                // move blocks
                prevBlock = block;
                block = null;
                computationIteration++;
            }
            Console.WriteLine("Finished hashing");

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
        }

        /// <summary>
        /// Override the InitType of the current instance of ACH1.
        /// </summary>
        /// <param name="type">The type to override the current hash and FNK generation method.</param>
        public void OverrideMode(InitType type) => initType = type;

        /// <summary>
        /// Computes a File Name Key using the method specified in the constructor.
        /// </summary>
        /// <param name="input">Input data for the File Name Key Generator. Must be a string or a byte[]. The string can contain a file path or data to be sampled.</param>
        /// <param name="FNK">File Name Key byte[] output. Must be declared and used.</param>
        /// <returns>A 128 byte File Name Key.</returns>
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
                    else if (byteNameB1.Length != 64) // TODO: fix this bc i dont think its working
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

        public (int fullBlocks, int fileLength) InitSeqBR(object input)
        { return ((int)new FileInfo((string)input).Length / readCount, (int)new FileInfo((string)input).Length); }

        public int SeqBR(object input, int computeIteration, out byte[] readBytes) // sequential bytereader
        {
            readBytes = null;
            int? readCount = null;
            using (FileStream fs = new FileStream((string)input, FileMode.Open))
            {
                fs.Position = this.readCount * computeIteration;
                int fileLength = (int)new FileInfo((string)input).Length;
                int count = Math.Min(fileLength - (computeIteration * this.readCount), this.readCount);
                readCount = fs.Read(readBytes ??= new byte[count], 0, count);
            }
            return readCount ?? 0;
        }

        #region seeding functions

        #region block seeders (2 requried)
        // keep in mind these affect the block directly

        private void BlockSpike(in byte[] block)
        {
            int mult = 0;
            for (int i = 0; i < block.Length; i++)
            {
                mult = block[1023 - i] * spikeStrength;
                if (mult > 1023)
                    mult = mult - 1023;
                block[block[mult]] = (byte)(mult ^ block[mult]);
            }
                
        }

        private void BlockJump(in byte[] block) // this is causing nullref
        {
            for (int i = 0; i <= block.Length; i++)
            {
                if (!(i >= 1022)) // if not overflowing
                {
                    byte newByt = (byte)((JumpConstant - block[i]) * block[i + 2]);
                    if (newByt > 255)
                        newByt %= (byte)Math.Pow(2, 32);
                    block[i + 2] = newByt;
                }
                else
                {
                    byte newByt = (byte)((JumpConstant - block[i - 255]) * block[i - 253]);
                    if (newByt > 255)
                        newByt %= (byte)Math.Pow(2, 32);
                    block[i - 253] = newByt;
                }
            }
        }

        #endregion

        #region subblock seeding (4 required)

        /// <summary>
        /// A and B should have the same length ALWAYS, and should ALWAYS be fed subblocks only
        /// </summary>
        internal byte[] AddMod32(byte[] a, byte[] b)
        {
            byte[] output = new byte[a.Length];
            for (int i = 0; i <= input.Length; i++)
                output[i] = Convert.ToByte((a[i] + b[i]) % Math.Pow(2, 32));
            return output;
        }

        #endregion

        private int GenerateSeedConstant(in byte[] block, int computationIteration) // this doesnt work, not surprised lmao
        {
            // ok this is basically GSC(in B[], i) = f(i) = sin( (B[340] * (i + 10)) / 20) * cos((i + 10) ^ B[680]) ^ ( B[1020] * i)
            int iterWOffset = computationIteration + 10;
            return (int)Math.Sin(block[340] * iterWOffset / 20 * Math.Pow(Math.Cos(Math.Pow(iterWOffset, block[680])), block[1020] * iterWOffset)); // ouch
        }

        #endregion

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
        
        private byte[] CreatePadArray(byte b, int c)
        {
            byte[] result = new byte[c];
            for (int i = 0; i < c; i++)
                result[i] = b;
            return result;
        }

        private byte[] RotRight(byte[] a, int amount)
        { return a.Skip(a.Length - amount).Concat(a.Take(a.Length - amount)).ToArray(); }

        private byte[] RotLeft(byte[] a, int amount)
        { return a.Skip(amount).Concat(a.Take(amount)).ToArray(); }

        #endregion

        #endregion

        #endregion
    }
}
