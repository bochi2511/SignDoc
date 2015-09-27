using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class InvalidOutputFileException : Exception
    {
        public InvalidOutputFileException()
        {
        }

        public InvalidOutputFileException(string message) : base(message)
        {
        }

        public InvalidOutputFileException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidOutputFileException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}