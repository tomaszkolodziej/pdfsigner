package com.tolean.pdfsigner;

import com.itextpdf.text.BadElementException;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Image;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class PdfSigner {

    private CertificateManager certificateManager;
    private KeyStore keyStore;

    private String keyStorePath;
    private String keyStorePassword;

    private String publicCertificatePath;

    private String privateKeyAlias;
    private String privateKeyPassword;

    public PdfSigner() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        certificateManager = new CertificateManager();
    }

    public PdfSigner withKeyStore(final String keyStorePath, final String keyStorePassword) {
        this.keyStorePath = keyStorePath;
        this.keyStorePassword = keyStorePassword;
        return this;
    }

    public PdfSigner withPublicCertificate(final String publicKeyPath) {
        this.publicCertificatePath = publicKeyPath;
        return this;
    }

    public PdfSigner withPrivateKey(final String privateKeyAlias, final String privateKeyPassword) {
        this.privateKeyAlias = privateKeyAlias;
        this.privateKeyPassword = privateKeyPassword;
        return this;
    }

    public void sign(String sourcePdf, String destinationPdf, String imagePath, int[] imageRectanglePosition) throws GeneralSecurityException, IOException, DocumentException {
        if (sourcePdf == null || sourcePdf.isEmpty()) {
            throw new IllegalArgumentException("Source is required.");
        }

        if (destinationPdf == null || destinationPdf.isEmpty()) {
            throw new IllegalArgumentException("Destination is required.");
        }

        if (imageRectanglePosition == null || imageRectanglePosition.length != 4) {
            throw new IllegalArgumentException("Image rectangle position array should have 4 elements.");
        }

        final KeyStore keyStore = getKeyStore();
        final PrivateKey privateKey = getPrivateKey();
        final java.security.cert.Certificate[] certificates = keyStore.getCertificateChain(privateKeyAlias);

        PdfReader reader = new PdfReader(sourcePdf);
        PdfStamper stamper = PdfStamper.createSignature(reader, new FileOutputStream(destinationPdf), '\0');

        final PdfSignatureAppearance signatureAppearance = getSignatureAppearance(stamper, imagePath, imageRectanglePosition);

        ExternalSignature externalSignature = new PrivateKeySignature(privateKey, "SHA-256", "BC");
        ExternalDigest externalDigest = new BouncyCastleDigest();
        MakeSignature.signDetached(signatureAppearance, externalDigest, externalSignature, certificates, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
    }

    private PdfSignatureAppearance getSignatureAppearance(PdfStamper stamper, String imagePath, int[] imageRectanglePosition) throws BadElementException, IOException {
        PdfSignatureAppearance signatureAppearance = stamper.getSignatureAppearance();
        signatureAppearance.setCertificationLevel(PdfSignatureAppearance.CERTIFIED_NO_CHANGES_ALLOWED);

        if (imagePath != null && !imagePath.isEmpty()) {
            signatureAppearance.setSignatureGraphic(Image.getInstance(imagePath));
            signatureAppearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.GRAPHIC);
            signatureAppearance.setVisibleSignature(
                    new Rectangle(imageRectanglePosition[0], imageRectanglePosition[1], imageRectanglePosition[2], imageRectanglePosition[3]),
                    1,
                    "signature"
            );
        }

        return signatureAppearance;
    }

    private PrivateKey getPrivateKey() throws GeneralSecurityException, IOException {
        return certificateManager.getPrivateKey(getKeyStore(), privateKeyAlias, privateKeyPassword);
    }

    private KeyStore getKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        if (keyStore != null) {
            return keyStore;
        } else {
            keyStore = certificateManager.loadKeyStore(keyStorePath, keyStorePassword);
        }
        return keyStore;
    }

}
