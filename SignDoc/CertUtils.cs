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
        //public const String KeyContainerName = "p11#a28222455077f707"; // Jorge Moreira
        public const String KeyContainerName = "p11#05c56736152ef298"; // Cliente 
        public const String ProviderName = "eToken Base Cryptographic Provider";

        public static X509Certificate2 GetCertToken(String keyContainerName) {
            X509Store store = new X509Store("My");
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 cert = null;

            foreach (X509Certificate2 cert2 in store.Certificates)
            {
                if (cert2.HasPrivateKey)
                {
                    try { 
                        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert2.PrivateKey;
                        if (rsa == null) continue; // not smart card cert again
                        if (rsa.CspKeyContainerInfo.HardwareDevice) // sure - smartcard
                        {
                            if ((rsa.CspKeyContainerInfo.KeyContainerName == keyContainerName) && (rsa.CspKeyContainerInfo.ProviderName == ProviderName))
                            {
                                //we find it
                                cert = cert2;
                                break;
                            }
                        }
                    } catch (CryptographicException c)
                    {
                        Console.WriteLine(c.GetType().ToString());
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

        public static void GetTokenInfo()
        {
            X509Store store = new X509Store("My");
            
            store.Open(OpenFlags.ReadOnly);
            foreach (X509Certificate2 cert2 in store.Certificates)
            {
                
                if (cert2.HasPrivateKey)
                {
                 
                    try
                    {
                        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)cert2.PrivateKey;
                        
                        if (rsa == null) continue; // not smart card cert again
                        if (rsa.CspKeyContainerInfo.HardwareDevice) // sure - smartcard
                        {
                            
                            Console.WriteLine("=======================================================================");
                            Console.WriteLine("Issuer: " + cert2.Issuer);
                            Console.WriteLine("Subject: " + cert2.Subject);
                            Console.WriteLine("Serial: " + cert2.SerialNumber);
                            Console.WriteLine("ProviderName: " + rsa.CspKeyContainerInfo.ProviderName);
                            Console.WriteLine("KeyContainerName: " + rsa.CspKeyContainerInfo.KeyContainerName);
                            foreach (X509Extension extension in cert2.Extensions)
                            {
                                if (extension.Oid.FriendlyName == "Key Usage")
                                {
                                    X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                                    Console.WriteLine("Key Usage: " + ext.KeyUsages);
                                }
                            }
                        }
                    }
                    catch (CryptographicException c)
                    {
                        Console.WriteLine("Serial: " + cert2.SerialNumber);
                        Console.WriteLine("No se tiene acceso a la clave privada");
                    }
                }
            }
        }
    }
}
