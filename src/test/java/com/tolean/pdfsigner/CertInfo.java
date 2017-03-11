package com.tolean.pdfsigner;

import java.net.URL;

/**
 * Created by Tomasz Kołodziej
 */
public class CertInfo {

    public static final String PUBLIC_CERTIFICATE_PATH = getPath("tkolodziej.cer");
    public static final String KEYSTORE_PATH = getPath("keystore.jks");
    public static final String KEYSTORE_PASSWORD = "password";
    public static final String PRIVATE_KEY_ALIAS = "tkolodziej";
    public static final String PRIVATE_KEY_PASSWORD = "password";
    public static final String IMAGE = getPath("sign.png");

    private static String getPath(String fileName) {
        URL url = Thread.currentThread().getContextClassLoader().getResource(fileName);
        return url.getPath();
    }

}
