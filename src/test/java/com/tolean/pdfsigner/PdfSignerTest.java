package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;

import static com.tolean.pdfsigner.CertInfo.*;

public class PdfSignerTest {

    private static final String OUTPUT_SIGNED = "sample_signed.pdf";

    @Test
    public void shouldSign() throws DocumentException, GeneralSecurityException, IOException {
        getPdfSigner().sign(getPath("sample_without_sign.pdf"), OUTPUT_SIGNED, IMAGE, new int[]{72, 732, 144, 780});
    }

    private PdfSigner getPdfSigner() {
        return new PdfSigner()
                .withKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD)
                .withPublicCertificate(PUBLIC_CERTIFICATE_PATH)
                .withPrivateKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD);
    }

    private static String getPath(String fileName) {
        URL url = Thread.currentThread().getContextClassLoader().getResource(fileName);
        return url.getPath();
    }

}