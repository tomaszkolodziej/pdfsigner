package com.tolean.pdfsigner;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static com.tolean.pdfsigner.CertInfo.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CertificateManagerTest {

    private CertificateManager certificateManager;

    @Before
    public void setup() {
        certificateManager = new CertificateManager();
    }

    @Test
    public void shouldGetCertificate() throws IOException, CertificateException {
        Certificate certificate = certificateManager.getCertificate(PUBLIC_CERTIFICATE_PATH);
        assertEquals("X.509", certificate.getType());
    }

    @Test
    public void shouldLoadKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore keyStore = certificateManager.loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetPrivateKey() throws IOException, GeneralSecurityException {
        KeyStore keyStore = certificateManager.loadKeyStore(KEYSTORE_PATH, KEYSTORE_PASSWORD);
        PrivateKey privateKey = certificateManager.getPrivateKey(keyStore, PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD);
        assertNotNull(privateKey);
    }

}