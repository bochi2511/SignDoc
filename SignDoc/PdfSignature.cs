using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignDoc
{
    class PdfSignature
    {
        public static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert)
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

        public static void SignPdfCert(String SRC, String DEST, String Reason, String Location, ICollection<X509Certificate> chain, ICipherParameters pk)
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
    }
}
