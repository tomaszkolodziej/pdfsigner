package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;

import static com.tolean.pdfsigner.CertInfo.*;

public class PdfDecryptTest {

    @Test
    public void shouldDecrypt() throws DocumentException, GeneralSecurityException, IOException {
        getPdfDecrypt().decrypt("sample_without_sign.pdf", "sample_signed.pdf");
    }

    private PdfDecrypt getPdfDecrypt() {
        return new PdfDecrypt(KEYSTORE_PATH, KEYSTORE_PASSWORD, PUBLIC_CERTIFICATE_PATH, PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD);
    }

}