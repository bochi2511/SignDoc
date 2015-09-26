using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class CertificateNotFoundInTokenException : Exception
    {
        public CertificateNotFoundInTokenException()
        {
        }

        public CertificateNotFoundInTokenException(string message) : base(message)
        {
        }

        public CertificateNotFoundInTokenException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected CertificateNotFoundInTokenException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}