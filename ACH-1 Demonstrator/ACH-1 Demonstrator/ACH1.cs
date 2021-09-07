// Copyright 2021 Nathaniel Aquino, All rights reserved.
using System;
using System.IO;

namespace ACH_1_Demonstrator
{
    public class ACH1 : IDisposable // final implimentation of the class goes here
    {
        #region variables

        public InitType initType;
        private bool disposedValue;

        private bool computeSetupFlag = true;

        private uint[] prevBlock = new uint[32]; //32 blocks of 32 bit numbers to store 1024 bit block
        private uint[] block = new uint[32];

        private byte[] output;
        private byte[] input;

        private string path;

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


        protected virtual void Dispose(bool disposing) // GC comes later...
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null

                prevBlock = null;
                block = null;
                output = null;
                input = null;
                path = null;

                disposedValue = true;
            }
        }

        public void Dispose() // do not change
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region main function

        /// <summary>
        /// Returns a 1024 bit hash using ACH-1. Parameter input must be a string or a byte[].
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] ComputeHash(object input)
        {
            if (computeSetupFlag)
            {
                // reset vars
                Clear();

                // type matching
                var match = TypeMatch(input);
                if (!match.success)
                    throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");
                switch (match.type)
                {
                    case Type.tByte:
                        this.input = (byte[])input;
                        input = null;
                        break;
                    case Type.tString:
                        path = (string)input;
                        input = null;
                        this.input = File.ReadAllBytes(path);
                        break;
                    case Type.notFound: break;
                }

                // FNK Formation
                // (this is for another day)
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

        #endregion
    }
}
