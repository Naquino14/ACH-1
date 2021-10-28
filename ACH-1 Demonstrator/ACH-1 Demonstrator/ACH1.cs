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



        private byte[] FNK = new byte[128];

        private bool pathFlag = false;

        #region constants

        private readonly byte FNKPad = 0xAA,
            JumpConstant = 0xFF,
            MainSubblockPad = 0x15;

        private readonly int brs1Index = 380, // block rotation sample index
            brs2Index = 932,
            brs3Index = 4;

        private readonly int readCount = 448;

        private readonly int spikeStrength = 4;

        private readonly int RMC2MC1 = 150,
            RMC2MC2 = 26,
            RMC2MC3 = 240;

        private readonly int a = 0,
            b = 1,
            c = 2,
            d = 3,
            e = 4,
            f = 5,
            g = 6,
            h = 7;

        // dynamic constants

        private int SeedConstant;

        private byte RMC1C1 = 0x50,
            RMC1C2 = 0x78,
            RMC1C3 = 0x05,
            RMC2C1 = 0x96,
            RMC2C2 = 0x1A,
            RMC2C3 = 0xF0;

        #endregion

        #region enums

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

        #endregion

        #region initialization and disposal methods

        /// <summary>
        /// Create an instance of ACH-1 with the specified hash input type.
        /// </summary>
        /// <param name="initType">The initialization type for the input.</param>
        public ACH1(InitType initType) => this.initType = initType;


        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
                if (disposing)
                {
                    prevBlock = null;
                    block = null;

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
        public byte[] ComputeHash(object input, byte[] FNK) // for actual input, use this.input
        { return ComputeHash_(input, FNK); }

        private byte[] ComputeHash_(object input, byte[] FNKO = null) // todo: i forgor datastreams :skull:
        {
            #region setup

            if (computeSetupFlag)
            {
                #region type matching

                var match = TypeMatch(input);
                if (!match.success)
                    throw new ArgumentException($"Parameter input has an invalid type {input.GetType()}.");
                if (initType == InitType.file)
                    pathFlag = true;

                #endregion

                #region generate FNK

                bool FNKS = false;
                if (FNKO == null)
                {
                    FNKS = GetFNK(input, out byte[] GENFNK);
                    if (!FNKS)
                        throw new Exception("FNK Could not be generated");
                    FNK = GENFNK;
                    GENFNK = null;
                }

                computeSetupFlag = false;

                #endregion
            }

            #endregion

            #region major compute loop

            bool computeFlag = true;
            int computationIteration = 0;
            int read;
            while (computeFlag)
            {
                Console.WriteLine($"Iteration: {computationIteration}");

                #region getting the next main subblock

                computeFlag = false;
                (int fullBlocks, int fileLength) seqBrInfo = (0, 0);

                if (pathFlag) // case of a file, get input
                {
                    seqBrInfo = InitSeqBR(input);
                    read = SeqBR(input, computationIteration, out block);
                    computeFlag = !(read < readCount); // true if the computation isnt finished
                } else
                {
                    int targetIndex = readCount * computationIteration;
                    switch (initType)
                    {
                        case InitType.bytes:
                            Array.Copy((byte[])input, targetIndex, block, targetIndex, readCount);
                            computeFlag = !(block.Length < readCount);
                        break;
                        case InitType.text:
                            Array.Copy(Encoding.ASCII.GetBytes((string)input), targetIndex, block, targetIndex, readCount);
                        break;
                        case InitType.stream:
                            read = SeqSR(input, computationIteration, out block);
                            computeFlag = !(read < readCount);
                            break;
                    }

                }

                #endregion

                #region CB and block Formation

                if (block.Length < 448)
                    block = AddArray(block, CreatePadArray(MainSubblockPad, 448 - block.Length));

                byte[] CBKey = new byte[448];
                CBKey = AddArray(FNK, FNK);
                CBKey = AddArray(CBKey, FNK);
                byte[] CBFNKPad = CreatePadArray(FNKPad, 64);
                CBKey = AddArray(CBKey, CBFNKPad);
                block = AddArray(block, OTPArray(block, CBKey));
                block = AddArray(block, FNK);

                if (computationIteration > 0)
                    block = OTPArray(block, prevBlock);

                #endregion

                #region block seeding

                // get new sc every 10 iterations
                if (computationIteration % 10 == 9)
                    SeedConstant = GSC(block, computationIteration);

                block = RotRight(block, block[brs1Index]);
                BlockSpike(block);
                block = RotLeft(block, block[brs2Index]);
                BlockJump(block);
                block = RotRight(block, block[brs3Index]);

                #endregion

                #region subblock digestion

                // there are a ratio of 2:1 for subblocks:functions, so in this case i have 4 functions, and 8 subblocks named A,B,C,D,E,F,G,H
                // see notebook for method

                // create subblocks

                byte[][] sbs = new byte[8][];
                for (int i = 0; i <= sbs.Length - 1; i++)
                { sbs[i] = new byte[128]; Array.Copy(block, i * 128, sbs[i], 0, 128); }

                // create target sbs
                byte[][] tsbs = new byte[8][];
                for (int i = 0; i <= tsbs.Length - 1; i++)
                    tsbs[i] = new byte[128];

                // get func results

                byte[] m1o = M1(sbs[e], sbs[f], sbs[g], SeedConstant),
                    m2o = M2(sbs[c], sbs[b], sbs[a], SeedConstant),
                    rm1o = RM1(sbs[h], SeedConstant),
                    rm2o = RM2(sbs[g], SeedConstant);

                // pad seed constant and feed it downrange
                byte[] scp = CreatePadArray((byte)SeedConstant, 128);

                byte[] drc = AddMod8(m1o, scp); // downrange compression
                drc = AddMod8(m2o, drc);
                drc = AddMod8(rm1o, drc);
                drc = AddMod8(rm2o, drc);

                // IN ORDER, assign targets

                tsbs[a] = rm1o;
                tsbs[b] = rm2o;
                // split result at path C
                byte[] rc = AddMod8(m1o, sbs[c]);
                tsbs[c] = AddMod8(sbs[a], rc);
                // split result at path D
                byte[] rd = AddMod8(drc, sbs[d]);
                tsbs[d] = AddMod8(sbs[b], rd);
                // split result at path E
                byte[] re = AddMod8(m2o, sbs[e]);
                tsbs[e] = rc;
                tsbs[f] = rd;
                tsbs[g] = re;
                tsbs[h] = AddMod8(re, sbs[f]);

                // copy results to block (lazy route moment)

                for (int i = 0; i <= sbs.Length - 1; i++)
                    Array.Copy(sbs[i], 0, block, 0, 128);

                // clear subblocks
                sbs = null;
                tsbs = null;
                #endregion

                prevBlock = block;
                block = null;
                computationIteration++;
            }

            #endregion

            Console.WriteLine("Finished hashing");
            return prevBlock;
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
            SeedConstant = 0;
            block = null;
            prevBlock = null;
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
        public bool GetFNK(object input, out byte[] FNK) // I am thinking about upgrading all of the inittypes to work like InitType.file, but for now I am leaving it like this
        {
            System.Type typ = input.GetType();
            string path = "";
            object fileNameSample;
            if (typ == typeof(string))
                path = (string)input;
            else if (typ == typeof(FileStream))
                path = ((FileStream)input).Name;
            else if (typ == typeof(Stream))
            {
                byte[] buf = new byte[64];
                ((Stream)input).Read(buf, 0, 64);
                fileNameSample = buf;
            }
            else if (typ == typeof(MemoryStream))
            {
                byte[] buf = new byte[64];
                ((MemoryStream)input).Read(buf, 0, 64);
                fileNameSample = buf;
            }
            else if (typ == typeof(byte[]))
                ; // dont need to do anthing here actually
            else
                throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");

            fileNameSample = path.Split('\\')[path.Split('\\').Length - 1].Split('.')[0];
            byte[] byteNameB1 = new byte[64];
            byte[] byteNameB2 = new byte[byteNameB1.Length];
            byte[] FNKOTPPad = new byte[0];
            int r = 0;
            byte[] pad = new byte[] { FNKPad };

            path = null;
            switch (initType)
            {
                #region InitType.file

                case InitType.file:
                    //if (byteNameB1.Length < 64)
                    //{
                    //    byteNameB1 = Encoding.ASCII.GetBytes((string)fileNameSample);
                    //    r = 64 - byteNameB1.Length;
                    //    pad = CreatePadArray(FNKPad, r);
                    //    byteNameB1 = AddArray(byteNameB1, pad);

                    //    pad = null;
                    //    r = 0;
                    //}
                    //else if (byteNameB1.Length != 64) // TODO: fix this bc i dont think its working
                    //{
                    //    byteNameB1 = Encoding.ASCII.GetBytes((string)fileNameSample);
                    //    int fullBlocks = byteNameB1.Length / 64;
                    //    int seek = 64 * fullBlocks;
                    //    byte[] bnr = FCArray(byteNameB1, seek, 64 - (((fullBlocks + 1) * 64) - byteNameB1.Length));

                    //    byte[][] bnb1sbs = new byte[fullBlocks][];
                    //    for (int i = 0; i <= (fullBlocks - 1); i++)
                    //        bnb1sbs[i] = FCArray(byteNameB1, (i * 64), 64);

                    //    byteNameB1 = bnb1sbs[0];
                    //    foreach (byte[] subblock in bnb1sbs)
                    //    {
                    //        bool s1fo = true;
                    //        if (!s1fo)
                    //            byteNameB1 = OTPArray(byteNameB1, subblock);
                    //        else
                    //            s1fo = false;
                    //    }

                    //    bnr = null;
                    //    seek = 0;
                    //    fullBlocks = 0;
                    //    bnb1sbs = null;
                    //}
                    //FNKOTPPad = CreatePadArray(FNKPad, 64);
                    //byteNameB2 = OTPArray(byteNameB1, FNKOTPPad);
                    //FNK = AddArray(byteNameB1, byteNameB2);
                    //return true;

                    return FNKSubFunc(byteNameB1, byteNameB2, fileNameSample, r, pad, typeof(string), out FNKOTPPad, out FNK);
                #endregion

                #region InitType.stream (all types)

                case InitType.stream:
                    if (input.GetType() == typeof(FileStream))
                        return FNKSubFunc(byteNameB1, byteNameB2, fileNameSample, r, pad, typeof(FileStream), out FNKOTPPad, out FNK);
                    else if (input.GetType() == typeof(Stream))
                    {
                        throw new NotImplementedException();
                        byteNameB1 = (byte[])fileNameSample;
                        FNK = null;
                        return false;
                    } 
                    else if (input.GetType() == typeof(MemoryStream))
                    {
                        throw new NotImplementedException();
                        FNK = null;
                        return false;
                    }
                    break;

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

            try
            {
                throw new ArgumentException($"Could not compute FNK, potential type mismatch" +
                    $"\n(does your ACH-1 initialization type match your object input? You can change the ACH-1 initialization type with OverrideMode(InitType))" +
                    $"\nCurrent initialization type: {this.initType} | Current input type: {input.GetType()}.");
            } catch (Exception ex)
            { Console.WriteLine(ex.ToString()); }
            finally
            { FNK = null; }
            return false;
        }

        private bool FNKSubFunc(byte[] byteNameB1, byte[] byteNameB2, object fileNameSample, int r, byte[] pad, System.Type typ, out byte[] FNKOTPPad, out byte[] FNK  )
        {
            Console.WriteLine(typ);
            // typematch because type variables arent real for some reason
            if (typ == typeof(string))
                byteNameB1 = Encoding.ASCII.GetBytes((string)fileNameSample);
            else if (typ == typeof(FileStream))
            {
                var sometype = (FileStream)fileNameSample;
                Console.WriteLine(sometype.Name.GetType());
                //name = name.Split('\\')[((FileStream)fileNameSample).Name.Split('\\').Length - 1].Split('.')[0];
                //byteNameB1 = Encoding.ASCII.GetBytes(name);
                throw new Exception("breakpoint");
            }
            else
                throw new ArgumentException();


            if (byteNameB1.Length < 64)
            {
                r = 64 - byteNameB1.Length;
                pad = CreatePadArray(FNKPad, r);
                byteNameB1 = AddArray(byteNameB1, pad);

                pad = null;
                r = 0;
            }
            else if (byteNameB1.Length != 64) // TODO: fix this bc i dont think its working
            {
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
        }

        private (int fullBlocks, int fileLength) InitSeqBR(object input)
        { return ((int)new FileInfo((string)input).Length / readCount, (int)new FileInfo((string)input).Length); }

        private int SeqBR(object input, int computeIteration, out byte[] readBytes) // sequential bytereader
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

        private int SeqSR(object input, int computeIteration, out byte[] readBytes) // sequential streamreader
        {
            System.Type inputType = input.GetType();
            readBytes = null;
            int? readCount = null;

            if (inputType == typeof(Stream))
            { 
                ((Stream)input).Position = computeIteration * this.readCount; 
                readCount = ((Stream)input).Read(readBytes ??= new byte[this.readCount], 0, this.readCount); 
            }
            else if (inputType == typeof(FileStream))
            { 
                ((FileStream)input).Position = computeIteration * this.readCount; 
                readCount = ((FileStream)input).Read(readBytes ??= new byte[this.readCount], computeIteration * this.readCount, this.readCount); 
            }
            else if (inputType == typeof(MemoryStream))
            { 
                ((MemoryStream)input).Position = computeIteration * this.readCount; 
                readCount = ((MemoryStream)input).Read(readBytes ??= new byte[this.readCount], computeIteration * this.readCount, this.readCount); 
            }
            else
                throw new ArgumentException($"Parameter input has an invalid type {input.GetType()}.");
                    
            return readCount ?? 0;
        }

        #region seeding and subblock functions

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
                block[mult] = (byte)(mult ^ block[mult]);
            }

        }

        private void BlockJump(in byte[] block)
        {
            for (int i = 0; i <= block.Length; i++)
            {
                int target;
                byte newByt;
                if (!(i >= 1022))
                { target = i + 2; newByt = (byte)((JumpConstant - block[i]) * block[target]); }
                else
                { target = i - 253; newByt = (byte)((JumpConstant - block[i - 255]) * block[target]); }
                if (newByt > 255)
                    newByt %= 255;
                block[target] = newByt;
            }
        }

        #endregion

        #region subblock functions (4 required)

        /// <summary>
        /// A and B should have the same length ALWAYS, and should ALWAYS be fed subblocks only
        /// </summary>
        private byte[] AddMod8(byte[] a, byte[] b)
        {
            byte[] o = new byte[a.Length];
            for (int i = 0; i <= a.Length - 1; i++)
                o[i] = (byte)((a[i] + b[i]) % 255);
            return o;
        }

        private byte[] M1(byte[] a, byte[] b, byte[] c, int sc)
        {
            byte[] o = new byte[a.Length];
            for (int i = 0; i <= a.Length - 1; i++)
            o[i] = (byte)((a[i] ^ (b[i] * sc % 255)) & (~a[i] ^ c[i]) ^ ~(b[i] ^ c[i]));
            return o;
        }

        private byte[] M2(byte[] a, byte[] b, byte[] c, int sc)
        {
            byte[] o = new byte[a.Length];
            for (int i = 0; i<= a.Length - 1; i++)
                o[i] = (byte)(~((~a[i] & b[i]) ^ (a[i] & c[i]) ^ (~(b[i] & (c[i] * sc % 255)))) ^ (a[i] ^ b[i]) ^ (b[i] ^ c[i]));
            return o;
        }

        private byte[] RM1(byte[] a, int sc)
        {
            byte[] o = new byte[a.Length];
            if (sc == 0)
                sc += 11;
            RMC1C1 = (byte)(RMC1C1 * sc % 255);
            RMC1C2 = (byte)(RMC1C2 * sc % 255);
            RMC1C3 = (byte)(RMC1C3 * sc % 255);
            byte[] t1 = RotLeft(a, RMC1C1),
                t2 = RotRight(a, RMC1C2),
                t3 = RotLeft(a, RMC1C3);
            for (int i = 0; i <= a.Length - 1; i++)
                o[i] = (byte)(t1[i] ^ t2[i] ^ t3[i]);
            return o;
        }

        private byte[] RM2(byte[] a, int sc)
        {
            byte[] o = new byte[a.Length];
            if (sc == 0)
                sc += 12;
            RMC2C1 = (byte)(RMC2MC1 % sc);
            RMC2C2 = (byte)(RMC2MC2 % sc);
            RMC2C3 = (byte)(RMC2MC3 % sc);
            byte[] t1 = RotRight(a, RMC2C1),
                t2 = RotLeft(a, RMC2C2),
                t3 = RotRight(a, RMC2C3);
            for (int i = 0; i <= a.Length - 1; i++)
                o[i] = (byte)(t1[i] ^ t2[i] ^ t3[i]);
            return o;
        }

        #endregion

        private int GSC(in byte[] block, int ci)
        {
            if (ci == 0)
                ci += 13;
            ci %= 47; // this is the best* limit for randomness
            float t1 = MathF.Sin(block[340] * ci / 20);
            float t2 = MathF.Cos(MathF.Pow(ci, block[680] / 10));
            float t3 = (block[1020] * ci + 1) / 100;
            t2 = MathF.Pow(t2, t3);
            float val = t1 * t2;
            byte[] vb = BitConverter.GetBytes(val);
            vb = RotLeft(vb, 9); // IEEE754 says that the fraction starts at byte 9

            byte? result = null;

            foreach (byte byt in vb)
                if (byt != 0x0)
                { result = byt; break; }

            return result ?? 0;
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

        private byte[] OTPArray (byte[] input, byte[] key)
        {
            byte[] result = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                result[i] = (byte)(input[i] ^ key[i]);
            return result;
        }

        private void PrintArray(byte[] array, string name = "")
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

        #region events



        #endregion

    }

    public class ACHEventArgs : EventArgs 
    {
        public Message message;
        public enum Message
        {
            fail,
            success
        }
    }
}
