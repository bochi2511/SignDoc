using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;

using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System.IO;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Pkcs;

using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using System.Xml;

namespace SignDoc
{
    class Program
    {
        public const String ProviderName = "eToken Base Cryptographic Provider";
        public const String KeyContainerName = "p11#a28222455077f707";
        public const String StoreFileName = "certificado.pfx";
        public const String StorePasswd = "morocho2511";
        static void Main(string[] args)
        {
            /* ************************************************************************

                        Sign PDF with Token

            **************************************************************************/

            var pass = new SecureString();
            pass.AppendChar('Y');
            pass.AppendChar('a');
            pass.AppendChar('n');
            pass.AppendChar('e');
            pass.AppendChar('r');
            pass.AppendChar('i');
            pass.AppendChar('L');
            pass.AppendChar('2');
            pass.AppendChar('1');
            pass.AppendChar('1');
            pass.AppendChar('0');

            CspParameters csp = new CspParameters(1,
                                                    ProviderName,
                                                    KeyContainerName,
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
                return;
            }
            SignPdfToken("prueba.pdf", "prueba-firma-token.pdf", "Motivo", "Ubicación", cert);

            /***********************************************************************************************

                    Sign binary file with XML Signature with token
                    Using previous example Key and cert
            
            ***********************************************************************************************/

            RSACryptoServiceProvider tokenKey = (RSACryptoServiceProvider)cert.PrivateKey;

            String Ref1 = "27542.tif";
            String XmlSigFileName1 = Ref1 + ".firmaToken.xml";

            // Sign the detached resourceand save the signature in an XML file.

            SignDetachedResource(Ref1, XmlSigFileName1, tokenKey, cert);


            /***********************************************************************************************

                            Sign PDF with certificate in file (PKCS12)

            ************************************************************************************************/

            Pkcs12Store p12ks = new Pkcs12Store();
            FileStream fs = new FileStream(StoreFileName, FileMode.Open);
            p12ks.Load(fs, StorePasswd.ToCharArray());
            String alias = "";
            foreach (String al in p12ks.Aliases)
            {
                if (p12ks.IsKeyEntry(al) && p12ks.GetKey(al).Key.IsPrivate)
                {
                    alias = al;
                    break;
                }
            }
            AsymmetricKeyParameter pk = p12ks.GetKey(alias).Key;
            ICollection<X509Certificate> chain = new List<X509Certificate>();
            foreach (X509CertificateEntry entry in p12ks.GetCertificateChain(alias))
            {
                chain.Add(entry.Certificate);
            }
            SignPdfCert("prueba.pdf", "prueba-firma-cert.pdf", "Motivo", "Ubicacion", chain, pk);

            fs.Close();

            /**********************************************************************************************

                                Sign Binary File as XML Signature with pkcs12 certificate file
                                
            **********************************************************************************************/

            X509Certificate2 certxml = new X509Certificate2(StoreFileName, StorePasswd);

            RSACryptoServiceProvider Key = (RSACryptoServiceProvider)certxml.PrivateKey;

            String Ref = "27542.tif";
            String XmlSigFileName = Ref + ".firma.xml";

            // Sign the detached resourceand save the signature in an XML file.

            SignDetachedResource(Ref, XmlSigFileName, Key, certxml);


        }
        private static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert)
        {
            //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
            //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(cert.RawData) };
            IList<X509Certificate> chain = new List<X509Certificate>();
            X509Chain x509chain = new X509Chain();
            x509chain.Build(cert);
            foreach (X509ChainElement x509ChainElement in x509chain.ChainElements)
            {
                chain.Add(DotNetUtilities.FromX509Certificate(x509ChainElement.Certificate));
            }
            IExternalSignature externalSignature = new X509Certificate2Signature(cert, DigestAlgorithms.SHA512);
            PdfReader pdfReader = new PdfReader(SRC);
            FileStream signedPdf = new FileStream(DEST, FileMode.Create);  //the output pdf file
            PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, signedPdf, '\0');
            PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
            //here set signatureAppearance at your will
            signatureAppearance.Reason = Reason;
            signatureAppearance.Location = Location;
            signatureAppearance.SetVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
            //signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
            //MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
        }

        private static void SignPdfCert(String SRC, String DEST, String Reason, String Location, ICollection<X509Certificate> chain, ICipherParameters pk)
        {
            //Org.BouncyCastle.X509.X509CertificateParser cp = new Org.BouncyCastle.X509.X509CertificateParser();
            //Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[] { cp.ReadCertificate(cert.RawData) };

            IExternalSignature externalSignature = new PrivateKeySignature(pk, DigestAlgorithms.SHA512);
            PdfReader pdfReader = new PdfReader(SRC);
            FileStream signedPdf = new FileStream(DEST, FileMode.Create);  //the output pdf file
            PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, signedPdf, '\0');
            PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
            //here set signatureAppearance at your will
            signatureAppearance.Reason = Reason;
            signatureAppearance.Location = Location;
            signatureAppearance.SetVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "sig");
            //signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
            //MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
        }
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
                keyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.EndCertOnly));
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
