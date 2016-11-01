package com.tolean.pdfsigner;

import org.junit.Test;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by TOLEAN on 31.10.16.
 */
public class CertificateUtilTest {

    private static final String PUBLIC_KEY_LOCATION = "c:\\pdfsigner\\tomaszkolodziej.crt";
    private static final String KEYSTORE_LOCATION = "c:\\Documents and Settings\\Tomek\\.keystore";

    @Test
    public void shouldLoadPublicCertificate() throws IOException, CertificateException {
        final Certificate certificate = new CertificateUtil().getPublicCertificate(PUBLIC_KEY_LOCATION);
        assertEquals("X.509", certificate.getType());
    }

    @Test
    public void shouldLoadPrivateCertificate() throws IOException, GeneralSecurityException {
        final KeyStore keyStore = new CertificateUtil().getKeyStore(KEYSTORE_LOCATION, "tomaszkolodziej");
        final PrivateKey privateKey = new CertificateUtil().getPrivateKey(keyStore, "tomaszkolodziej", "tomaszkolodziej");
        assertNotNull(privateKey);
    }

}