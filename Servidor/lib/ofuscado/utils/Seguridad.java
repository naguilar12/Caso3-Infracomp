// 
// Decompiled by Procyon v0.5.30
// 

package utils;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import java.util.Date;
import java.util.Random;
import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.Cipher;
import java.security.Key;

public class Seguridad
{
    public static byte[] a(final byte[] array, final Key key, String string) {
        string = String.valueOf(string) + ((string.equals("DES") || string.equals("AES")) ? "/ECB/PKCS5Padding" : "");
        final Cipher instance = Cipher.getInstance(string);
        instance.init(1, key);
        return instance.doFinal(array);
    }
    
    public static byte[] b(final byte[] array, final Key key, String string) {
        string = String.valueOf(string) + ((string.equals("DES") || string.equals("AES")) ? "/ECB/PKCS5Padding" : "");
        final Cipher instance = Cipher.getInstance(string);
        instance.init(2, key);
        return instance.doFinal(array);
    }
    
    public static byte[] c(final byte[] array, final Key key, final String s) {
        final Cipher instance = Cipher.getInstance(s);
        instance.init(1, key);
        return instance.doFinal(array);
    }
    
    public static byte[] d(final byte[] array, final Key key, final String s) {
        final Cipher instance = Cipher.getInstance(s);
        instance.init(2, key);
        return instance.doFinal(array);
    }
    
    public static byte[] e(final byte[] array, final Key key, final String s) {
        final Mac instance = Mac.getInstance(s);
        instance.init(key);
        return instance.doFinal(array);
    }
    
    public static boolean a(final byte[] array, final Key key, final String s, final byte[] array2) {
        final byte[] e = e(array, key, s);
        if (e.length != array2.length) {
            return false;
        }
        if (!Arrays.equals(e, array2)) {
            return false;
        }
        for (int i = 0; i < e.length; ++i) {
            if ((e[i] & array2[i]) == array2[i]) {
                return false;
            }
        }
        return true;
    }
    
    public static SecretKey a(final String s) {
        int n = 0;
        if (s.equals("DES")) {
            n = 64;
        }
        else if (s.equals("AES")) {
            n = 128;
        }
        else if (s.equals("Blowfish")) {
            n = 128;
        }
        else if (s.equals("RC4")) {
            n = 128;
        }
        if (n == 0) {
            throw new NoSuchAlgorithmException();
        }
        final KeyGenerator instance = KeyGenerator.getInstance(s, "BC");
        instance.init(n);
        return instance.generateKey();
    }
    
    public static X509Certificate a(final KeyPair keyPair) {
        final PublicKey public1 = keyPair.getPublic();
        final PrivateKey private1 = keyPair.getPrivate();
        final PublicKey public2 = keyPair.getPublic();
        final JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
        final JcaX509v3CertificateBuilder jcaX509v3CertificateBuilder = new JcaX509v3CertificateBuilder(new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), new BigInteger(128, new SecureRandom()), new Date(System.currentTimeMillis()), new Date(System.currentTimeMillis() + 8640000000L), new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), public1);
        ((X509v3CertificateBuilder)jcaX509v3CertificateBuilder).addExtension(X509Extension.subjectKeyIdentifier, false, (ASN1Encodable)jcaX509ExtensionUtils.createSubjectKeyIdentifier(public1));
        ((X509v3CertificateBuilder)jcaX509v3CertificateBuilder).addExtension(X509Extension.authorityKeyIdentifier, false, (ASN1Encodable)jcaX509ExtensionUtils.createAuthorityKeyIdentifier(public2));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(((X509v3CertificateBuilder)jcaX509v3CertificateBuilder).build(new JcaContentSignerBuilder("MD5withRSA").setProvider("BC").build(private1)));
    }
    
    public static KeyPair a() {
        final KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
        instance.initialize(1024, new SecureRandom());
        return instance.generateKeyPair();
    }
}
