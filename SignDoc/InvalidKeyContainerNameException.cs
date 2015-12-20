using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class InvalidKeyContainerNameException : Exception
    {
        public InvalidKeyContainerNameException()
        {
        }

        public InvalidKeyContainerNameException(string message) : base(message)
        {
        }

        public InvalidKeyContainerNameException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidKeyContainerNameException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}