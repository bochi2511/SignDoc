using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
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
        static readonly private List<X509Certificate> certificates = new List<X509Certificate>();
        private static readonly int NO_SIGN_IN_FILE = 20;
        private static readonly int MULTIPLE_SIGN_IN_FILE = 21;
        private static readonly int VAL_OK_CERTS_NOK = 22;
        private static readonly int DOC_INTEGRITY_INVALID = 23;
        private static readonly int SIG_NOT_COVER_FULL_DOC = 24;
        private static readonly int CER_STATUS_NOT_VERIFIED = 25;
        private static readonly int VAL_OK_CER_VALID_NOCRLOROCSP = 25;



        public static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert, String tokenPassword, String keyContainerName)
        {
            SignPdfToken(SRC, DEST, Reason, Location, cert, tokenPassword, keyContainerName, "36", "748", "144", "780", 8);
        }
        public static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert, String tokenPassword, String keyContainerName, String llx, String lly, String urx, String ury)
        {
            SignPdfToken(SRC, DEST, Reason, Location, cert, tokenPassword, keyContainerName, llx, lly, urx, ury, 8);
        }
        public static void SignPdfToken(String SRC, String DEST, String Reason, String Location, X509Certificate2 cert, String tokenPassword, String keyContainerName, String llx, String lly, String urx, String ury, int fontSize)
        {
            var pass = new SecureString();
            foreach (char c in tokenPassword.ToCharArray())
            {
                pass.AppendChar(c);
            }
            Console.WriteLine("Password cargada");

            CspParameters csp = new CspParameters(1,
                                                    CertUtils.ProviderName,
                                                    keyContainerName,
                                                    new System.Security.AccessControl.CryptoKeySecurity(),
                                                    pass);
         
            Console.WriteLine("CSP cargada");
            try
            {
                RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(csp);
                // the pin code will be cached for next access to the smart card
            }
            catch (Exception ex)
            {
                Console.WriteLine("Crypto error: " + ex.Message + " " + ex.GetType().ToString());
                throw ex;
            }
            Console.WriteLine("Crypto Provider cargado");
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
            BaseFont bf = BaseFont.CreateFont();
            signatureAppearance.Layer2Font = new Font(bf, fontSize);
            signatureAppearance.CertificationLevel = PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED;
            signatureAppearance.SetVisibleSignature(new Rectangle(float.Parse(llx), float.Parse(lly), float.Parse(urx), float.Parse(ury)), 1, "sig");
            //signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
            //MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
        }

        public static void SignPdfCert(String SRC, String DEST, String Reason, String Location, String certPassword, String certFile)
        {
            SignPdfCert(SRC, DEST, Reason, Location, certPassword, certFile, "36", "748", "144", "780", 8);
        }
        public static void SignPdfCert(String SRC, String DEST, String Reason, String Location, String certPassword, String certFile, String llx, String lly, String urx, String ury)
        {
            SignPdfCert(SRC, DEST, Reason, Location, certPassword, certFile, llx, lly, urx, ury, 8);
        }

        public static void GetPdfSize(String pdfFile)
        {
            PdfReader pdfReader = new PdfReader(pdfFile);
            Program.logLine("page size" + pdfReader.GetPageSize(1));
            Console.WriteLine(pdfReader.GetPageSize(1).ToString().Substring(11, pdfReader.GetPageSize(1).ToString().IndexOf("(")-11));
        }

        public static void SignPdfCert(String SRC, String DEST, String Reason, String Location, String certPassword, String certFile, String llx, String lly, String urx, String ury, int fontSize)
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
            Program.logLine("page size" + pdfReader.GetPageSize(1));
            
            PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, signedPdf, '\0');
            PdfSignatureAppearance signatureAppearance = pdfStamper.SignatureAppearance;
            //here set signatureAppearance at your will
            signatureAppearance.Reason = Reason;
            signatureAppearance.Location = Location;
            BaseFont bf = BaseFont.CreateFont();
            signatureAppearance.Layer2Font = new Font(bf, fontSize);           
            signatureAppearance.SetVisibleSignature(new Rectangle(float.Parse(llx), float.Parse(lly), float.Parse(urx), float.Parse(ury)), 1, "sig");
            //signatureAppearance.SignatureRenderingMode = PdfSignatureAppearance.RenderingMode.DESCRIPTION;
            MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CMS);
            //MakeSignature.SignDetached(signatureAppearance, externalSignature, chain, null, null, null, 0, CryptoStandard.CADES);
        }

        static public int VerificaFirma(String pdffile)
        {
            Console.WriteLine(pdffile);
            PdfReader reader = new PdfReader(pdffile);
            AcroFields fields = reader.AcroFields;
            if (fields.TotalRevisions == 1)
            {
                List<String> names = fields.GetSignatureNames();
                string name = names[0];
                PdfPKCS7 pkcs7 = fields.VerifySignature(name);
                if (fields.SignatureCoversWholeDocument(name))
                {
                    if (pkcs7.Verify())
                    {
                        Console.WriteLine("Firma: Validación correcta");
                        X509Certificate[] certs = pkcs7.SignCertificateChain;
                        DateTime cal = pkcs7.SignDate;
                        X509Store store = new X509Store(StoreName.Root);
                        store.Open(OpenFlags.ReadOnly);
                        foreach (var tmpcert in store.Certificates)
                        {
                            certificates.Add(DotNetUtilities.FromX509Certificate(tmpcert));
                        }
                        store.Close();

                        store = new X509Store(StoreName.CertificateAuthority);
                        store.Open(OpenFlags.ReadOnly);
                        foreach (var tmpcert in store.Certificates)
                        {
                            certificates.Add(DotNetUtilities.FromX509Certificate(tmpcert));
                        }
                        store.Close();

                        IList<iTextSharp.text.pdf.security.VerificationException> errors = CertificateVerification.VerifyCertificates(certs, certificates, null, cal);
                        if (errors.Count == 0)
                        {
                            Console.WriteLine("Certificado: Validado correctamente con certificados de confianza");
                            for (int i = 0; i < certs.Length; ++i)
                            {
                                X509Certificate cert = certs[i];
                                Console.WriteLine("=== Certificado " + i + " ===");
                                ShowCertificateInfo(cert, cal.ToLocalTime());
                            }
                            X509Certificate signCert = certs[0];
                            X509Certificate issuerCert = (certs.Length > 1 ? certs[1] : null);
                            Console.WriteLine("=== Verificando si existía revocación del certificado al momento de la firma ===");
                            if (CheckRevocation(pkcs7, signCert, issuerCert, cal) == 0)
                            {
                                return 0;
                            }
                            else
                            {
                                return VAL_OK_CER_VALID_NOCRLOROCSP;
                            }    
                        }
                        else
                        {
                            foreach (object error in errors)
                                Console.WriteLine(error);
                            return VAL_OK_CERTS_NOK;
                        }
                            
                    }
                    else
                    {
                        Console.WriteLine("Error: La firma no valida, integridad del documento violada");
                        return DOC_INTEGRITY_INVALID;
                    }
                }
                else
                {
                    Console.WriteLine("Error: La firma no cubre todo el documento");
                    return SIG_NOT_COVER_FULL_DOC;
                }

            }
            else if (fields.TotalRevisions == 0)
            {
                Console.WriteLine("Error: Archivo no contiene firmas");
                return NO_SIGN_IN_FILE;
            }
            else
            {
                Console.WriteLine("Error: Archivo con mas de una firma");
                return MULTIPLE_SIGN_IN_FILE;
            }
        }

        static public PdfPKCS7 VerifySignatureOld(AcroFields fields, String name)
        {
            Console.WriteLine("Signature covers whole document: " + fields.SignatureCoversWholeDocument(name));
            Console.WriteLine("Document revision: " + fields.GetRevision(name) + " of " + fields.TotalRevisions);
            PdfPKCS7 pkcs7 = fields.VerifySignature(name);
            Console.WriteLine("Integrity check OK? " + pkcs7.Verify());
            return pkcs7;
        }
        static public PdfPKCS7 VerifySignature(AcroFields fields, String name)
        {
            PdfPKCS7 pkcs7 = VerifySignatureOld(fields, name);
            X509Certificate[] certs = pkcs7.SignCertificateChain;
            DateTime cal = pkcs7.SignDate;
            X509Store store = new X509Store(StoreName.Root);
            store.Open(OpenFlags.ReadOnly);
            foreach (var tmpcert in store.Certificates)
            {
                certificates.Add(DotNetUtilities.FromX509Certificate(tmpcert));
            }
            store.Close();

            store = new X509Store(StoreName.CertificateAuthority);
            store.Open(OpenFlags.ReadOnly);
            foreach (var tmpcert in store.Certificates)
            {
                certificates.Add(DotNetUtilities.FromX509Certificate(tmpcert));
            }
            store.Close();

            IList<iTextSharp.text.pdf.security.VerificationException> errors = CertificateVerification.VerifyCertificates(certs, certificates, null, cal);
            if (errors == null)
                Console.WriteLine("Certificates verified against the KeyStore");
            else
                foreach (object error in errors)
                    Console.WriteLine(error);
            for (int i = 0; i < certs.Length; ++i)
            {
                X509Certificate cert = certs[i];
                Console.WriteLine("=== Certificate " + i + " ===");
                ShowCertificateInfo(cert, cal.ToLocalTime());
            }
            X509Certificate signCert = certs[0];
            X509Certificate issuerCert = (certs.Length > 1 ? certs[1] : null);
            Console.WriteLine("=== Checking validity of the document at the time of signing ===");
            CheckRevocation(pkcs7, signCert, issuerCert, cal);
            Console.WriteLine("=== Checking validity of the document today ===");
            CheckRevocation(pkcs7, signCert, issuerCert, DateTime.Now);
            return pkcs7;
        }

        public static int CheckRevocation(PdfPKCS7 pkcs7, X509Certificate signCert, X509Certificate issuerCert, DateTime date)
        {
            List<BasicOcspResp> ocsps = new List<BasicOcspResp>();
            if (pkcs7.Ocsp != null)
                ocsps.Add(pkcs7.Ocsp);
            OcspVerifier ocspVerifier = new OcspVerifier(null, ocsps);
            List<VerificationOK> verification =
                ocspVerifier.Verify(signCert, issuerCert, date);
            if (verification.Count == 0)
            {
                List<X509Crl> crls = new List<X509Crl>();
                if (pkcs7.CRLs != null)
                    foreach (X509Crl crl in pkcs7.CRLs)
                        crls.Add(crl);
                CrlVerifier crlVerifier = new CrlVerifier(null, crls);
                verification.AddRange(crlVerifier.Verify(signCert, issuerCert, date));
            }
            if (verification.Count == 0)
            {
                Console.WriteLine("No se pudo verificar estado de revocación del certificado por CRL ni OCSP");
                return CER_STATUS_NOT_VERIFIED;
            }
            else
            {
                foreach (VerificationOK v in verification)
                    Console.WriteLine(v);
                return 0;
            }
        }

        static public void ShowCertificateInfo(X509Certificate cert, DateTime signDate)
        {
            Console.WriteLine("Issuer: " + cert.IssuerDN);
            Console.WriteLine("Subject: " + cert.SubjectDN);
            Console.WriteLine("Valido dede: " + cert.NotBefore.ToString("yyyy-MM-dd HH:mm:ss.ff"));
            Console.WriteLine("Valido hasta: " + cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss.ff"));
            try
            {
                cert.CheckValidity(signDate);
                Console.WriteLine("El certificado era valido al momento de la firma.");
            }
            catch (CertificateExpiredException e)
            {
                Console.WriteLine("El certificado estaba expirado al momento de la firma. " + e.ToString());
            }
            catch (CertificateNotYetValidException e)
            {
                Console.WriteLine("El certificado no era válido aún al momento de la firma. " + e.ToString());
            }
            try
            {
                cert.CheckValidity();
                Console.WriteLine("El certificado sigue siendo válido.");
            }
            catch (CertificateExpiredException e)
            {
                Console.WriteLine("El certificado ha expirado. " + e.ToString());
            }
            catch (CertificateNotYetValidException e)
            {
                Console.WriteLine("El certificado no es válido aún. " + e.ToString());
            }
        }

        static public void VerifySignatures(String path)
        {
            Console.WriteLine(path);
            PdfReader reader = new PdfReader(path);
            AcroFields fields = reader.AcroFields;
            List<String> names = fields.GetSignatureNames();
            foreach (string name in names)
            {
                Console.WriteLine("===== " + name + " =====");
                VerifySignature(fields, name);
            }
            Console.WriteLine();
        }
        static public SignaturePermissions InspectSignature(AcroFields fields, String name, SignaturePermissions perms)
        {
            IList<AcroFields.FieldPosition> fps = fields.GetFieldPositions(name);
            if (fps != null && fps.Count > 0)
            {
                AcroFields.FieldPosition fp = fps[0];
                Rectangle pos = fp.position;
                if (pos.Width == 0 || pos.Height == 0)
                {
                    Console.WriteLine("Invisible signature");
                }
                else
                {
                    Console.WriteLine("Field en página {0}; llx: {1}, lly: {2}, urx: {3}; ury: {4}",
                        fp.page, pos.Left, pos.Bottom, pos.Right, pos.Top);
                }
            }
            PdfPKCS7 pkcs7 = fields.VerifySignature(name);
            Console.WriteLine("Algoritmo de Digest: " + pkcs7.GetHashAlgorithm());
            Console.WriteLine("Algoritmo Encripción: " + pkcs7.GetEncryptionAlgorithm());
            Console.WriteLine("Filter subtype: " + pkcs7.GetFilterSubtype());
            X509Certificate cert = pkcs7.SigningCertificate;
            Console.WriteLine("Nombre del firmante: " + CertificateInfo.GetSubjectFields(cert).GetField("CN"));
            if (pkcs7.SignName != null)
                Console.WriteLine("Nombre Alternativo del firmante: " + pkcs7.SignName);

            Console.WriteLine("Firmado en: " + pkcs7.SignDate.ToString("yyyy-MM-dd HH:mm:ss.ff"));
            if (!pkcs7.TimeStampDate.Equals(DateTime.MaxValue))
            {
                Console.WriteLine("TimeStamp: " + pkcs7.TimeStampDate.ToString("yyyy-MM-dd HH:mm:ss.ff"));
                TimeStampToken ts = pkcs7.TimeStampToken;
                Console.WriteLine("TimeStamp service: " + ts.TimeStampInfo.Tsa);
                Console.WriteLine("Timestamp verificado? " + pkcs7.VerifyTimestampImprint());
            }
            Console.WriteLine("Ubicación: " + pkcs7.Location);
            Console.WriteLine("Motivo: " + pkcs7.Reason);
            PdfDictionary sigDict = fields.GetSignatureDictionary(name);
            PdfString contact = sigDict.GetAsString(PdfName.CONTACTINFO);
            if (contact != null)
                Console.WriteLine("Datos de contacto: " + contact);
            perms = new SignaturePermissions(sigDict, perms);
            Console.WriteLine("Tipo de firma: " + (perms.Certification ? "certification" : "approval"));
            //Console.WriteLine("Filling out fields allowed: " + perms.FillInAllowed);
            //Console.WriteLine("Adding annotations allowed: " + perms.AnnotationsAllowed);
            foreach (SignaturePermissions.FieldLock Lock in perms.FieldLocks)
            {
                Console.WriteLine("Lock: " + Lock);
            }
            return perms;
        }

        static public void InspectSignatures(String path)
        {
            Console.WriteLine(path);
            PdfReader reader = new PdfReader(path);
            AcroFields fields = reader.AcroFields;
            List<String> names = fields.GetSignatureNames();
            SignaturePermissions perms = null;
            foreach (String name in names)
            {
                Console.WriteLine("===== " + name + " =====");
                perms = InspectSignature(fields, name, perms);
            }
            Console.WriteLine();
        }
    }
}
