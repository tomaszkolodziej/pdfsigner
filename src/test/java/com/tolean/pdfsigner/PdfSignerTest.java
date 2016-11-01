package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Created by TOLEAN on 31.10.16.
 */
public class PdfSignerTest {

    private static final String PUBLIC_CERTIFICATE_PATH = "c:\\pdfsigner\\tomaszkolodziej.crt";
    private static final String KEYSTORE_PATH = "c:\\Documents and Settings\\Tomek\\.keystore";
    private static final String KEYSTORE_PASSWORD = "tomaszkolodziej";
    private static final String PRIVATE_KEY_ALIAS = "tomaszkolodziej";
    private static final String PRIVATE_KEY_PASSWORD = "tomaszkolodziej";
    private static final String IMAGE = "c:\\pdfsigner\\sign.png";

    @Test
    public void shouldEncrypt() throws DocumentException, GeneralSecurityException, IOException {
        getPdfSigner().encrypt("c:\\pdfsigner\\sample_decrypted.pdf", "c:\\pdfsigner\\sample_encrypted.pdf");
    }

    @Test
    public void shouldDecrypt() throws DocumentException, GeneralSecurityException, IOException {
        getPdfSigner().decrypt("c:\\pdfsigner\\sample_encrypted.pdf", "c:\\pdfsigner\\sample_decrypted.pdf");
    }

    @Test
    public void shouldSign() throws DocumentException, GeneralSecurityException, IOException {
        getPdfSigner().sign("c:\\pdfsigner\\sample_without_sign.pdf", "c:\\pdfsigner\\sample_signed.pdf", IMAGE, new int[]{ 72, 732, 144, 780 });
    }

    private PdfSigner getPdfSigner() {
        return new PdfSigner()
                .withKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD)
                .withPublicCertificate(PUBLIC_CERTIFICATE_PATH)
                .withPrivateKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD);
    }

}