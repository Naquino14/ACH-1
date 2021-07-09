// Copyright 2021 Nathaniel Aquino, All rights reserved.
using System;

namespace ACH_1_Demonstrator
{
    public class ACH1 : IDisposable // final implimentation of the class goes here
    {
        #region initialization and disposal methods

        public ACH1InitType initType;
        private bool disposedValue;

        public ACH1(ACH1InitType initType) => this.initType = initType;
        public enum ACH1InitType
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
                disposedValue = true;
            }
        }

        public void Dispose() // do not change
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Returns a 1024 bit hash using ACH-1. Parameter input must be a string or a byte[].
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public byte[] ComputeHash(object input)
        {
            // type matching
            var match = TypeMatch(input);
            if (!match.success)
                throw new ArgumentException("Parameter input has an invalid type " + input.GetType() + ".");

            return null;
        }

        #endregion

        #region methods

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

        #endregion
    }
}
