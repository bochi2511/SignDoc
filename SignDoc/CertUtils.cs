using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SignDoc
{
    class CertUtils
    {
        public const String KeyContainerName = "p11#a28222455077f707";
        public const String ProviderName = "eToken Base Cryptographic Provider";

        public static X509Certificate2 GetCertToken() {
            X509Store store = new X509Store("My");
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;

            foreach (X509Certificate2 cert2 in store.Certificates)
            {
                if (cert2.HasPrivateKey)
                {
                    RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert2.PrivateKey;
                    if (rsa == null) continue; // not smart card cert again
                    if (rsa.CspKeyContainerInfo.HardwareDevice) // sure - smartcard
                    {
                        if ((rsa.CspKeyContainerInfo.KeyContainerName == KeyContainerName) && (rsa.CspKeyContainerInfo.ProviderName == ProviderName))
                        {
                            //we find it
                            cert = cert2;
                            break;
                        }
                    }
                }
            }
            if (cert == null)
            {
                Console.WriteLine("Certificate not found");
                throw new CertificateNotFoundInTokenException();
            } else
            {
                return cert;
            }
        }
    }
}
