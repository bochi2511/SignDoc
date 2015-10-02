using System;
using System.Collections;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace SignDoc
{
    class TiffSignature
    {
        public static void SignDetachedResource(string inputFile, string outputSignatureXML, string certFile, String certPassword)
        {
            X509Certificate2 certxml = new X509Certificate2(certFile, certPassword);

            RSACryptoServiceProvider Key = (RSACryptoServiceProvider)certxml.PrivateKey;

            
            String XmlSigFileName = outputSignatureXML;

            // Sign the detached resourceand save the signature in an XML file.
            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml();

            // Assign the key to the SignedXml object.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();

            // Add the passed Refrence to the reference object.
            reference.Uri = inputFile;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue((RSA)Key));
            if (certxml != null)
            {
                KeyInfoX509Data kinfox509 = new KeyInfoX509Data(certxml, X509IncludeOption.WholeChain);
                kinfox509.AddIssuerSerial(certxml.Issuer, certxml.SerialNumber);
                kinfox509.AddSubjectName(certxml.Subject);
                keyInfo.AddClause(kinfox509);
            }
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter xmltw = new XmlTextWriter(XmlSigFileName, new UTF8Encoding(false));
            xmlDigitalSignature.WriteTo(xmltw);
            xmltw.Close();
        }
        public static void GetTiffInfo(string XmlSigFileName)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            xmlDocument.Load(XmlSigFileName);

            // Create a new SignedXMl object.
            SignedXml signedXml = new SignedXml();

            // Find the "Signature" node and create a new 
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);

            // Check the signature and return the result. 
            IEnumerator enumerator = signedXml.KeyInfo.GetEnumerator();

            X509Certificate2 cert = new X509Certificate2();

            while (enumerator.MoveNext())
            {
                if (enumerator.Current is KeyInfoX509Data)
                {
                    var current = (KeyInfoX509Data)enumerator.Current;
                    if (current.Certificates.Count != 0)
                    {
                        cert = (X509Certificate2) current.Certificates[0];
                        break;
                    }
                }
            }
            Console.WriteLine("Emisor: " + cert.Issuer);
            Console.WriteLine("Subject: " + cert.Subject);
            Console.WriteLine("Serial: " + cert.SerialNumber);
            Console.WriteLine("Thumbprint: " + cert.Thumbprint);
            Console.WriteLine("Valido desde: " + cert.NotBefore);
            Console.WriteLine("Válido hasta: " + cert.NotAfter);
        }
        public static Boolean VerifyDetachedSignature(string XmlSigFileName)
        {
            // Create a new XML document.
            XmlDocument xmlDocument = new XmlDocument();

            // Load the passed XML file into the document.
            xmlDocument.Load(XmlSigFileName);

            // Create a new SignedXMl object.
            SignedXml signedXml = new SignedXml();

            // Find the "Signature" node and create a new 
            // XmlNodeList object.
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");

            // Load the signature node.
            signedXml.LoadXml((XmlElement)nodeList[0]);
            
            // Check the signature and return the result. 
            return signedXml.CheckSignature();
        }

        public static void SignDetachedResourceWithToken(String inputFile, String outputXmlFile, String tokenPassword)
        {
            var pass = new SecureString();
            foreach (char c in tokenPassword.ToCharArray())
            {
                pass.AppendChar(c);
            }


            CspParameters csp = new CspParameters(1,
                                                    CertUtils.ProviderName,
                                                    CertUtils.KeyContainerName,
                                                    new System.Security.AccessControl.CryptoKeySecurity(),
                                                    pass);
            try
            {
                RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(csp);
                // the pin code will be cached for next access to the smart card
            }
            catch (Exception ex)
            {
                Console.WriteLine("Crypto error: " + ex.Message);
                return;
            }
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
                        if ((rsa.CspKeyContainerInfo.KeyContainerName == CertUtils.KeyContainerName) && (rsa.CspKeyContainerInfo.ProviderName == CertUtils.ProviderName))
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
                return;
            }
            RSACryptoServiceProvider tokenKey = (RSACryptoServiceProvider)cert.PrivateKey;
            
            // Sign the detached resourceand save the signature in an XML file.
            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml();

            // Assign the key to the SignedXml object.
            signedXml.SigningKey = tokenKey;

            // Create a reference to be signed.
            Reference reference = new Reference();

            // Add the passed Refrence to the reference object.
            reference.Uri = inputFile;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue((RSA)tokenKey));
            if (cert != null)
            {
                KeyInfoX509Data kinfox509 = new KeyInfoX509Data(cert, X509IncludeOption.EndCertOnly);
                kinfox509.AddIssuerSerial(cert.Issuer, cert.SerialNumber);
                kinfox509.AddSubjectName(cert.Subject);
                keyInfo.AddClause(kinfox509);
            }
            signedXml.KeyInfo = keyInfo;

            // Compute the signature.
            signedXml.ComputeSignature();

            // Get the XML representation of the signature and save
            // it to an XmlElement object.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Save the signed XML document to a file specified
            // using the passed string.
            XmlTextWriter xmltw = new XmlTextWriter(outputXmlFile, new UTF8Encoding(false));
            xmlDigitalSignature.WriteTo(xmltw);
            xmltw.Close();

        }
    }
}
