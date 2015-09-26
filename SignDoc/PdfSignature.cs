using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignDoc
{
    class PdfSignature
    {
        public static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert, String tokenPassword)
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

        public static void SignPdfCert(String SRC, String DEST, String Reason, String Location, String certPassword, String certFile)
        {
            Pkcs12Store p12ks = new Pkcs12Store();
            FileStream fs = new FileStream(certFile, FileMode.Open);
            p12ks.Load(fs, certPassword.ToCharArray());
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

            fs.Close();
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
    }
}
