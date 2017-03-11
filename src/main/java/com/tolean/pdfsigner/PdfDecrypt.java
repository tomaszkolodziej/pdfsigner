package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;

/**
 * Created by Tomasz Kołodziej
 */
public class PdfDecrypt {

    private CertificateManager certificateManager;

    private String keyStorePath;
    private String keyStorePassword;

    private String publicCertificatePath;

    private String privateKeyAlias;
    private String privateKeyPassword;

    private PdfDecrypt() {
        // do nothing
    }

    public PdfDecrypt(String keyStorePath, String keyStorePassword,
                      String publicCertificatePath, String privateKeyAlias, String privateKeyPassword) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        this.publicCertificatePath = publicCertificatePath;
        this.privateKeyAlias = privateKeyAlias;
        this.privateKeyPassword = privateKeyPassword;

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        certificateManager = new CertificateManager();
    }

    public void decrypt(final String sourcePdf, final String destinationPdf) throws IOException, GeneralSecurityException, DocumentException {
        if (sourcePdf == null || sourcePdf.isEmpty()) {
            throw new IllegalArgumentException("Source is required.");
        }

        if (destinationPdf == null || destinationPdf.isEmpty()) {
            throw new IllegalArgumentException("Destination is required.");
        }

        java.security.cert.Certificate publicCertificate = certificateManager.getCertificate(publicCertificatePath);
        KeyStore keyStore = certificateManager.loadKeyStore(keyStorePath, keyStorePassword);
        PrivateKey privateKey = certificateManager.getPrivateKey(keyStore, privateKeyAlias, privateKeyPassword);
        PdfReader reader = new PdfReader(sourcePdf, publicCertificate, privateKey, "BC");
        PdfStamper stamper = new PdfStamper(reader, new FileOutputStream(destinationPdf));
        stamper.close();
        reader.close();
    }

}
