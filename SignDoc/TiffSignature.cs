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
        public static void SignDetachedResource(string ReferenceString, string XmlSigFileName, RSA Key, X509Certificate2 cert)
        {
            // Create a SignedXml object.
            SignedXml signedXml = new SignedXml();

            // Assign the key to the SignedXml object.
            signedXml.SigningKey = Key;

            // Create a reference to be signed.
            Reference reference = new Reference();

            // Add the passed Refrence to the reference object.
            reference.Uri = ReferenceString;

            // Add the reference to the SignedXml object.
            signedXml.AddReference(reference);

            // Add an RSAKeyValue KeyInfo (optional; helps recipient find key to validate).
            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue((RSA)Key));
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
