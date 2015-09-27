using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class InvalidTokenPasswordException : Exception
    {
        public InvalidTokenPasswordException()
        {
        }

        public InvalidTokenPasswordException(string message) : base(message)
        {
        }

        public InvalidTokenPasswordException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidTokenPasswordException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}