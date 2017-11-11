// 
// Decompiled by Procyon v0.5.30
// 

package ServidorNovasoft;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.io.IOException;
import java.security.Key;
import utils.Transformacion;
import java.io.Writer;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import java.io.StringWriter;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.Seguridad;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.util.io.pem.PemReader;
import java.io.StringReader;
import java.security.NoSuchAlgorithmException;
import java.awt.FontFormatException;
import java.io.Reader;
import java.io.InputStreamReader;
import java.net.Socket;
import java.io.PrintWriter;
import java.io.BufferedReader;

public class Worker
{
    private static void a(final Exception ex) {
        System.out.println(ex.getMessage());
        ex.printStackTrace();
    }
    
    private static String a(final BufferedReader bufferedReader) {
        final String line = bufferedReader.readLine();
        System.out.println("<<CLNT: " + line);
        return line;
    }
    
    private static void a(final PrintWriter printWriter, final String s) {
        printWriter.println(s);
        System.out.println(">>SERV: " + s);
    }
    
    public static void a(final Socket socket) {
        Label_1222: {
            try {
                final PrintWriter printWriter = new PrintWriter(socket.getOutputStream(), true);
                final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                final String a = a(bufferedReader);
                if (!a.equals("HOLA")) {
                    a(printWriter, "Error en el formato. Cerrando conexion");
                    throw new FontFormatException(a);
                }
                a(printWriter, "OK");
                final String a2 = a(bufferedReader);
                if (!a2.contains(":") || !a2.split(":")[0].equals("ALGORITMOS")) {
                    a(printWriter, "Error en el formato. Cerrando conexion");
                    throw new FontFormatException(a2);
                }
                final String[] split = a2.split(":");
                if (!split[1].equals("Blowfish") && !split[1].equals("AES") && !split[1].equals("DES") && !split[1].equals("RC4")) {
                    a(printWriter, "ERROR");
                    throw new NoSuchAlgorithmException();
                }
                if (!split[2].equals("RSA")) {
                    a(printWriter, "ERROR");
                    throw new NoSuchAlgorithmException();
                }
                if (!split[3].equals("HMACMD5") && !split[3].equals("HMACSHA1") && !split[3].equals("HMACSHA256")) {
                    a(printWriter, "ERROR");
                    throw new NoSuchAlgorithmException();
                }
                a(printWriter, "OK");
                X509Certificate certificate;
                try {
                    final String a3 = a(bufferedReader);
                    final String[] split2 = a3.split(":");
                    if (!split2[0].equals("CERTCLNT")) {
                        a(printWriter, "Error en el formato. Cerrando conexion");
                        throw new FontFormatException(a3);
                    }
                    String s = String.valueOf("") + split2[1] + "\n";
                    String s2;
                    for (s2 = a(bufferedReader); !s2.equals("-----END CERTIFICATE-----"); s2 = a(bufferedReader)) {
                        s = String.valueOf(s) + s2 + "\n";
                    }
                    final PemReader pemReader = new PemReader((Reader)new StringReader(String.valueOf(s) + s2));
                    certificate = new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(pemReader.readPemObject().getContent()));
                    pemReader.close();
                }
                catch (Exception ex) {
                    a(printWriter, "ERROR");
                    a(printWriter, ex.getMessage());
                    ex.printStackTrace();
                    throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
                }
                KeyPair keyPair = Seguridad.a();
                try {
                    Security.addProvider((Provider)new BouncyCastleProvider());
                    final KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA", "BC");
                    instance.initialize(1024);
                    keyPair = instance.generateKeyPair();
                    final X509Certificate a4 = Seguridad.a(keyPair);
                    final StringWriter stringWriter = new StringWriter();
                    final JcaPEMWriter jcaPEMWriter = new JcaPEMWriter((Writer)stringWriter);
                    jcaPEMWriter.writeObject((Object)a4);
                    jcaPEMWriter.flush();
                    jcaPEMWriter.close();
                    a(printWriter, "CERTSRV:" + stringWriter.toString());
                }
                catch (Exception ex2) {
                    ex2.printStackTrace();
                }
                a(bufferedReader);
                a(printWriter, Transformacion.a(Seguridad.d(Transformacion.a(a(bufferedReader)), keyPair.getPrivate(), split[2])));
                if (!a(bufferedReader).equalsIgnoreCase("OK")) {
                    a(printWriter, "ERROR");
                    throw new FontFormatException("Error, no se paso el reto 1.");
                }
                final SecretKey a5 = Seguridad.a(split[1]);
                a(printWriter, Transformacion.a(Seguridad.c(a5.getEncoded(), certificate.getPublicKey(), split[2])));
                final String[] split3 = Transformacion.a(Seguridad.b(Transformacion.a(a(bufferedReader)), a5, split[1])).split(",");
                try {
                    final String s3 = split3[0];
                    final String s4 = split3[1];
                    if (s3 == "" || s4 == "") {
                        throw new Exception("El usuario y la clave no pueden ser vacios.");
                    }
                }
                catch (Exception ex13) {
                    a(printWriter, Transformacion.a(Seguridad.a("ERROR".getBytes(), a5, split[1])));
                    throw new FontFormatException("Error: no se introdujo el usuario y la clave de manera adecuada");
                }
                final String a6 = Transformacion.a(Seguridad.a("OK".getBytes(), a5, split[1]));
                a(printWriter, a6);
                final String[] split4 = a(bufferedReader).split(":");
                if (Seguridad.a(Seguridad.b(Transformacion.a(split4[0]), a5, split[1]), a5, split[3], Seguridad.b(Transformacion.a(split4[1]), a5, split[1]))) {
                    a(printWriter, a6);
                    break Label_1222;
                }
                a(printWriter, Transformacion.a(Seguridad.a("ERROR".getBytes(), a5, split[1])));
                throw new FontFormatException("Error, no se cumple integridad en la consulta.");
            }
            catch (NullPointerException ex3) {
                a(ex3);
            }
            catch (IOException ex4) {
                a(ex4);
            }
            catch (FontFormatException ex5) {
                a(ex5);
            }
            catch (NoSuchAlgorithmException ex6) {
                a(ex6);
            }
            catch (InvalidKeyException ex7) {
                a(ex7);
            }
            catch (IllegalStateException ex8) {
                a(ex8);
            }
            catch (NoSuchPaddingException ex9) {
                ex9.printStackTrace();
            }
            catch (IllegalBlockSizeException ex10) {
                ex10.printStackTrace();
            }
            catch (BadPaddingException ex11) {
                ex11.printStackTrace();
            }
            catch (Exception ex12) {
                ex12.printStackTrace();
            }
            finally {
                try {
                    socket.close();
                }
                catch (Exception ex14) {}
            }
            try {
                socket.close();
            }
            catch (Exception ex15) {}
        }
    }
}
