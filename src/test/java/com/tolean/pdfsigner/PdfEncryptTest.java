package com.tolean.pdfsigner;

import com.itextpdf.text.DocumentException;
import org.junit.AfterClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static com.tolean.pdfsigner.CertInfo.PUBLIC_CERTIFICATE_PATH;

public class PdfEncryptTest {

    private static final String OUTPUT_ENCRYPTED = "sample_encrypted.pdf";

    @AfterClass
    public static void teardown() {
        new File(OUTPUT_ENCRYPTED).delete();
    }

    @Test
    public void shouldEncrypt() throws DocumentException, GeneralSecurityException, IOException {
        getPdfEncrypt().encrypt("sample_decrypted.pdf", OUTPUT_ENCRYPTED);
    }

    private PdfEncrypt getPdfEncrypt() {
        return new PdfEncrypt(PUBLIC_CERTIFICATE_PATH);
    }

}