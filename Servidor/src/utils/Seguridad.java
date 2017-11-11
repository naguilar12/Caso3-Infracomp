/**
 * 
 */
package utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import org.bouncycastle.asn1.x500.X500Name; 
import org.bouncycastle.asn1.x509.*; 
import org.bouncycastle.cert.X509v3CertificateBuilder; 
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Clase que contiene metodos static que proveen la seguridad del protocolo, implementando la librer�a mas reciente de bouncy.
 * Infraestructura Computacional 201720
 * Universidad de los Andes.
 * 
 * @author Jairo Emilio Bautista
 * @author Mariana Rodriguez
 */
public class Seguridad {	
	
	//Algoritmos simetricos
	public static final String RC4 = "RC4";
	public static final String BLOWFISH = "Blowfish";
	public static final String AES = "AES";
	public static final String DES = "DES";

	//Algoritmos asimetricos
	public static final String RSA = "RSA";
	
	//HMAC
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";

	/**
	 * Metodo que hace un cifrado simetrico delos bytes de entrada.
	 * @param msg El mensaje a cifrar.
	 * @param key La llave usada para cifrar.
	 * @param algo El algoritmo a cifrar.
	 * @return Los bytes cifrados que devolvio el algoritmo.
	 * @throws IllegalBlockSizeException Si hubo un error con el tamanio de la llave.
	 * @throws BadPaddingException Si hubo un error con el algoritmo.
	 * @throws InvalidKeyException Si la llave no es valida.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws NoSuchPaddingException Si el padding no es valido.
	 */
	public static byte[] symmetricEncryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	/**
	 * Metodo que hace un descifrado simetrico de los bytes de entrada.
	 * @param msg El mensaje a descifrar.
	 * @param key La llave de cifrado.
	 * @param algo El algoritmo de cifrado.
	 * @return Los bytes descifrados que devolvio el algoritmo.
	 * @throws IllegalBlockSizeException Si hubo un error con el tamao de la llave.
	 * @throws BadPaddingException Si hubo un error con el algoritmo.
	 * @throws InvalidKeyException Si la llave no es valida.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws NoSuchPaddingException Si el padding no es valido.
	 */
	public static byte[] symmetricDecryption (byte[] msg, Key key , String algo)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		algo = algo + 
				(algo.equals(DES) || algo.equals(AES)?"/ECB/PKCS5Padding":"");
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	/**
	 * Metodo que hace un cifrado asimetrico de los bytes de entrada.
	 * @param msg El mensaje a cifrar.
	 * @param key La llave usada para cifrar.
	 * @param algo El algoritmo a cifrar.
	 * @return Los bytes cifrados que devolvio el algoritmo.
	 * @throws IllegalBlockSizeException Si hubo un error con el tama��o de la llave.
	 * @throws BadPaddingException Si hubo un error con el algoritmo.
	 * @throws InvalidKeyException Si la llave no es valida.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws NoSuchPaddingException Si el padding no es valido.
	 */
	public static byte[] asymmetricEncryption (byte[] msg, Key key , String algo) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, 
			NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.ENCRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	/**
	 * Metodo que hace un descifrado simetrico de los bytes de entrada.
	 * @param msg El mensaje cifrado.
	 * @param key La llave de cifrado.
	 * @param algo El algoritmo de cifrado.
	 * @return Los bytes descifrados que devolvio el algoritmo.
	 * @throws IllegalBlockSizeException Si hubo un error con el tama��o de la llave.
	 * @throws BadPaddingException Si hubo un error con el algoritmo.
	 * @throws InvalidKeyException Si la llave no es valida.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws NoSuchPaddingException Si el padding no es valido.
	 */
	public static byte[] asymmetricDecryption (byte[] msg, Key key , String algo) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			IllegalBlockSizeException, BadPaddingException {
		Cipher decifrador = Cipher.getInstance(algo); 
		decifrador.init(Cipher.DECRYPT_MODE, key); 
		return decifrador.doFinal(msg);
	}

	/**
	 * Metodo que genera un codigo HMAC a partir de una llave, un mensaje y un algoritmo.
	 * @param msg El mensaje sobre el cual se va a aplicar el digest.
	 * @param key La llave que se usa para HMAC.
	 * @param algo El algoritmo de generacion del codigo HMAC.
	 * @return El digests en un arreglo de bytes.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws InvalidKeyException Si la llave no es valida.
	 * @throws IllegalStateException Si no fue posible hacer el digest.
	 * @throws UnsupportedEncodingException Si la codificacion no es valida.
	 */
	public static byte[] hmacDigest(byte[] msg, Key key, String algo) throws NoSuchAlgorithmException,
	InvalidKeyException, IllegalStateException, UnsupportedEncodingException {
		Mac mac = Mac.getInstance(algo);
		mac.init(key);

		byte[] bytes = mac.doFinal(msg);
		return bytes;
	}

	/**
	 * Metodo que verifica que un codigo HMAC corresponda con un mensaje dado.
	 * @param msg El mensaje que se quiere comprobar.
	 * @param key La llave simetrica con la cual se genero el HMAC.
	 * @param algo El algoritmo de generacion de HMAC.
	 * @param hash El hash que acompa��a al mensaje.
	 * @return La verificacion de que el mensaje y el codigo hmac coincidan.
	 * @throws Exception Si hubo un error al generar un mensaje HMAC.
	 */
	public static boolean verificarIntegridad(byte[] msg, Key key, String algo, byte [] hash ) throws Exception
	{
		byte [] nuevo = hmacDigest(msg, key, algo);
		if (nuevo.length != hash.length) {
			System.out.println("longitud");
			return false;
		}
		if(!Arrays.equals(nuevo, hash)) {
			System.out.println("arrays");
			return false;
		}
		for (int i = 0; i < nuevo.length ; i++) {
			if ((nuevo[i] & hash[i]) != hash[i]) {System.out.println("comp");return false;}
		}
		return true;
	}

	/**
	 * Metodo que se encarga de generar la llave simetrica de cualquier algoritmo.
	 * @param algoritmo - El algoritmo asociado con la llave
	 * @return La llave simetrica.
	 * @throws NoSuchProviderException Si no hay un proveedor de seguridad.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 */
	public static SecretKey keyGenGenerator(String algoritmo) 
			throws NoSuchAlgorithmException, NoSuchProviderException	{
		int tamLlave = 0;
		if (algoritmo.equals(DES))
			tamLlave = 64;
		else if (algoritmo.equals(AES))
			tamLlave = 128;
		else if (algoritmo.equals(BLOWFISH))
			tamLlave = 128;
		else if (algoritmo.equals(RC4))
			tamLlave = 128;

		if (tamLlave == 0) throw new NoSuchAlgorithmException();

		KeyGenerator keyGen;
		SecretKey key;
		keyGen = KeyGenerator.getInstance(algoritmo,"BC");
		keyGen.init(tamLlave);
		key = keyGen.generateKey();
		return key;
	}

	/**
	 * Metodo que crea un nuevo certificado digital siguiendo el formato X509 a partir del par de llaves dado usando las librerias de bouncycastle
	 * @param pair La pareja de llaves publica y privada necesarias para la generacion del certificado
	 * @return Un nuevo certificado autofirmado con formato X509.
	 * @throws InvalidKeyException Si las llaves no son validas.
	 * @throws NoSuchProviderException Si el proveedor de seguridad no esta bien establecido.
	 * @throws SignatureException Si no se pudo generar el certificado.
	 * @throws IllegalStateException Si no se pudo generar el certificado.
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 * @throws CertificateException Si no se pudo generar el certificado.
	 */

	public static X509Certificate generateV3Certificate(KeyPair pair)   throws Exception
	{
		PublicKey  subPub  = pair.getPublic();
		PrivateKey issPriv = pair.getPrivate();
		PublicKey  issPub  = pair.getPublic();

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		X509v3CertificateBuilder v3CertGen = new JcaX509v3CertificateBuilder(
				new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), 
				new BigInteger(128, new SecureRandom()), 
				new Date(System.currentTimeMillis()), 
				new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)), 
				new X500Name("CN=0.0.0.0, OU=None, O=None, L=None, C=None"), subPub);

		v3CertGen.addExtension(
				X509Extension.subjectKeyIdentifier,
				false,
				extUtils.createSubjectKeyIdentifier(subPub));

		v3CertGen.addExtension(
				X509Extension.authorityKeyIdentifier,
				false,
				extUtils.createAuthorityKeyIdentifier(issPub));

		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(v3CertGen.build(new JcaContentSignerBuilder("MD5withRSA").setProvider("BC").build(issPriv)));
	}


	/**
	 * Metodo que genera el par de llaves de 1024 bits necesarias para la creacion del certificado
	 * @return El objeto que contiene tanto la llave publica como la privada
	 * @throws NoSuchAlgorithmException Si el algoritmo no es valido.
	 */
	public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {

		KeyPairGenerator kpGen = KeyPairGenerator.getInstance(RSA);
		kpGen.initialize(1024, new SecureRandom());
		return kpGen.generateKeyPair();
	}



}
