﻿using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;


using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;

using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace SignDoc
{
    class Program
    {
 
        private static readonly int GENERAL_PROGRAM_ERROR = 1;
        private static readonly int BAD_PARAMETER_ERROR = 2;
        private static readonly int SIGNATURE_VERIFICATION_FAILED = 3;

        public static void Main(string[] args)
        {
            //Test();
            if (args.Length < 1)
            {
                ExitWithBadParams();
            }
            /*
            args[0] = mode := signpdffile|signpdftoken|signtifffile|signtifftoken|validatetiff|validatepdf 
            */
            System.Console.WriteLine("Starting SignDoc in mode:" + args[0]);
            try
            {
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
                }
                else
                {
                    ExitWithBadParams();
                }
            }
            catch (SignatureVerificacionException e)
            {
                System.Console.WriteLine("SignDoc ends with exception " + e.Message);
                System.Environment.Exit(SIGNATURE_VERIFICATION_FAILED);
            }
            catch (Exception e)
            {
                System.Console.WriteLine("SignDoc ends with exception " +  e.Message);
                System.Environment.Exit(GENERAL_PROGRAM_ERROR);
            }
            Environment.Exit(0);
        }

       

        private static void ParseValiedatePdf(string[] args)
        {
            
        }

        /*
        args[1] tiff file input
        */
        private static void ParseValiedateTiff(string[] args)
        {
            if (!TiffSignature.VerifyDetachedSignature(args[1]))
            {
                Console.WriteLine(args[1] + " fallo verificacion");
                throw new SignatureVerificacionException();
            }
        }

        /*
        args[1] tiff file input
        args[2] xmlSignature file output
        args[3] tokenPassword
        */
        private static void ParseSignTiffToken(string[] args)
        {
            TiffSignature.SignDetachedResourceWithToken(args[0], args[1], args[2]);
        }

        /*
     args[1] tiff file input
     args[2] xmlSignature file output
     args[3] CertFile
     args[4] CertPassword
     */
        private static void ParseSignTiffFile(string[] args)
        {
            TiffSignature.SignDetachedResource(args[1], args[2], args[3], args[4]);
        }

        /*
       args[1] pdf file input
       args[2] pdf file output
       args[3] token password
       args[4] reason
       args[5] location
       */
        private static void ParseSignPdfToken(string[] args)
        {
            if (!Validator.FileExist(args[1]))
            {
                throw new FileNotFoundException(args[1]);
            }
            if (args[2] == null || "".Equals(args[3]))
            {

            }
            if (args[3] == null || "".Equals(args[3]))
            {

            }

            PdfSignature.SignPdfToken(args[1], args[2], args[4], args[5], CertUtils.GetCertToken(), args[3]);

        }

        /*
        args[1] pdf file input
        args[2] pdf file output
        args[3] reason
        args[4] location
        args[5] CertFile
        args[6] CertPassword
        */
        private static void ParseSignPdfFile(string[] args)
        {
            PdfSignature.SignPdfCert(args[1], args[2], args[3],args[4], args[6], args[5]);
        }

        private static void ExitWithBadParams()
        {
            System.Console.WriteLine("Error bad parameters");
            System.Console.WriteLine("Use: SignDoc ");
            System.Environment.Exit(BAD_PARAMETER_ERROR);
        }

       
        
        
    }
}
