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
        private static readonly int GENERAL_PROGRAM_ERROR = 1;
        private static readonly int BAD_PARAMETER_ERROR = 2;

        static void Main(string[] args)
        {
            Test();
            if (args.Length < 1)
            {
                ExitWithBadParams();
            }
            /*
            args[0] = mode := signpdffile|signpdftoken|signtifffile|signtifftoken|validatetiff|validatepdf 
            */
            System.Console.WriteLine("Starting SignDoc in mode:" + args[0]);
            if ("signpdffile".Equals(args[0]))
            {
                ParseSignPdfFile(args);
            }
            else if ("signpdftoken".Equals(args[0]))
            {
                ParseSignPdfToken(args);
            }
            else if ("signtifffile".Equals(args[0]))
            {
                ParseSignTiffFile(args);
            }
            else if ("signtifftoken".Equals(args[0]))
            {
                ParseSignTiffToken(args);
            }
            else if ("validatetiff".Equals(args[0]))
            {
                ParseValiedateTiff(args);
            }
            else if ("validatepdf".Equals(args[0]))
            {
                ParseValiedatePdf(args);
            } else
            {
                ExitWithBadParams();
            }
            System.Console.WriteLine("SignDoc ends");
            System.Environment.Exit(0);
        }

        /*
        args[1] pdf file input
        args[2] pdf file output
        args[3] token password
        
        */

        private static void ParseValiedatePdf(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ParseValiedateTiff(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ParseSignTiffToken(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ParseSignTiffFile(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ParseSignPdfToken(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ParseSignPdfFile(string[] args)
        {
            throw new NotImplementedException();
        }

        private static void ExitWithBadParams()
        {
            System.Console.WriteLine("Error bad parameters");
            System.Console.WriteLine("Use: SignDoc ");
            System.Environment.Exit(BAD_PARAMETER_ERROR);
        }

        private static int SignPDFKeyInFile(string pdfInPath,
                                            string pdfOutPath,
                                            string keyFile,
                                            string keyFilePassword)
        {

            return GENERAL_PROGRAM_ERROR;
        }

        private static int SignPDFKeyInToken(string pdfInPath,
                                             string pdfOutPath,
                                             string tokenPassword)
        {

            return GENERAL_PROGRAM_ERROR;
        }

        private static int SignTIFFKeyInFile(string tiffInPath,
                                             string xmlOutPath,
                                             string keyFile,
                                             string keyFilePassword)
        {

            return GENERAL_PROGRAM_ERROR;
        }

        private static int SignTIFFKeyInToken(string tdfInPath,
                                              string xmlOutPath,
                                              string tokenPassword)
        {

            return GENERAL_PROGRAM_ERROR;
        }

        private static int ValidateSignaturePDF(string pdfInPath)
        {

            return GENERAL_PROGRAM_ERROR;
        }

        private static int ValidateSignatureTIFF(string tdfInPath,
                                                 string xmlInSignature)
        {

            return GENERAL_PROGRAM_ERROR;
        }


        static void Test()
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
            PdfSignature.SignPdfToken("prueba.pdf", "prueba-firma-token.pdf", "Motivo", "Ubicación", cert);

            /***********************************************************************************************

                    Sign binary file with XML Signature with token
                    Using previous example Key and cert
            
            ***********************************************************************************************/

            RSACryptoServiceProvider tokenKey = (RSACryptoServiceProvider)cert.PrivateKey;

            String Ref1 = "27542.tif";
            String XmlSigFileName1 = Ref1 + ".firmaToken.xml";

            // Sign the detached resourceand save the signature in an XML file.

            TiffSignature.SignDetachedResource(Ref1, XmlSigFileName1, tokenKey, cert);


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
            PdfSignature.SignPdfCert("prueba.pdf", "prueba-firma-cert.pdf", "Motivo", "Ubicacion", chain, pk);

            fs.Close();

            /**********************************************************************************************

                                Sign Binary File as XML Signature with pkcs12 certificate file
                                
            **********************************************************************************************/

            X509Certificate2 certxml = new X509Certificate2(StoreFileName, StorePasswd);

            RSACryptoServiceProvider Key = (RSACryptoServiceProvider)certxml.PrivateKey;

            String Ref = "27542.tif";
            String XmlSigFileName = Ref + ".firma.xml";

            // Sign the detached resourceand save the signature in an XML file.

            TiffSignature.SignDetachedResource(Ref, XmlSigFileName, Key, certxml);


        }
        
        
    }
}
