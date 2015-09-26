using System;
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

            
            String XmlSigFileName = outputSignatureXML + ".firma.xml";

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
                KeyInfoX509Data kinfox509 = new KeyInfoX509Data(certxml, X509IncludeOption.EndCertOnly);
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
    }
}
