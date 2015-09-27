using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class InvalidCertificatePasswordException : Exception
    {
        public InvalidCertificatePasswordException()
        {
        }

        public InvalidCertificatePasswordException(string message) : base(message)
        {
        }

        public InvalidCertificatePasswordException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected InvalidCertificatePasswordException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}