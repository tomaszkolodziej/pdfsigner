package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;

/**
 * Created by Tomasz Kołodziej
 */
public class PdfEncrypt {

    private CertificateManager certificateManager;

    private String publicCertificatePath;

    private PdfEncrypt() {
        // do nothing
    }

    public PdfEncrypt(String publicCertificatePath) {
        this.publicCertificatePath = publicCertificatePath;

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        certificateManager = new CertificateManager();
    }

    public void encrypt(final String sourcePdf, final String destinationPdf) throws IOException, DocumentException, CertificateException {
        if (sourcePdf == null || sourcePdf.isEmpty()) {
            throw new IllegalArgumentException("Source is required.");
        }

        if (destinationPdf == null || destinationPdf.isEmpty()) {
            throw new IllegalArgumentException("Destination is required.");
        }

        PdfReader reader = new PdfReader(sourcePdf);
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(destinationPdf));
        java.security.cert.Certificate cert = certificateManager.getCertificate(publicCertificatePath);
        stamper.setEncryption(new java.security.cert.Certificate[]{cert}, new int[]{ PdfWriter.ALLOW_PRINTING }, PdfWriter.ENCRYPTION_AES_128);
        stamper.close();
        reader.close();
    }

}
