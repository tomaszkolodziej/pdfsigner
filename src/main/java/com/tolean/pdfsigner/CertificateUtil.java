package com.tolean.pdfsigner;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by TOLEAN on 31.10.16.
 */
public class CertificateUtil {

    public Certificate getPublicCertificate(String publicCertificatePath) throws IOException, CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new FileInputStream(publicCertificatePath));
        return certificate;
    }

    public PrivateKey getPrivateKey(KeyStore keyStore, String privateCertificateAlias, String privateCertificatePassword) throws GeneralSecurityException, IOException {
        return (PrivateKey) keyStore.getKey(privateCertificateAlias, privateCertificatePassword.toCharArray());
    }

    public KeyStore getKeyStore(String keyStorePath, String keyStorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(keyStorePath), keyStorePassword.toCharArray());
        return keyStore;
    }

}
