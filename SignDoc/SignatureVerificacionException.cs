using System;
using System.Runtime.Serialization;

namespace SignDoc
{
    [Serializable]
    internal class SignatureVerificacionException : Exception
    {
        public SignatureVerificacionException()
        {
        }

        public SignatureVerificacionException(string message) : base(message)
        {
        }

        public SignatureVerificacionException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected SignatureVerificacionException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}