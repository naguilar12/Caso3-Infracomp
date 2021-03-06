package infracomp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import javax.xml.bind.DatatypeConverter;

public class Cliente {

	boolean ejecutar = true;
	Socket sock = null;
	PrintWriter escritor = null;
	BufferedReader lector = null;
	PrivateKey priKeyCliente = null;
	PublicKey pubKeyServer = null;
	SecretKey simKey = null;
	String algSim = "";
	String algDig = "";
	FileWriter file1;
	BufferedWriter bw1;
	PrintWriter pw1;
	FileWriter file2;
	BufferedWriter bw2;
	PrintWriter pw2;
	FileWriter file3;
	BufferedWriter bw3;
	PrintWriter pw3;

	private final static String ALGORITMO_ASIM = "RSA";
	private final static String PROVIDER = "BC";

	public Cliente()
	{
		try {
			file1 = new FileWriter("TiemposAuServ.txt",true); 
			bw1 = new BufferedWriter(file1);
			pw1 = new PrintWriter(bw1);
			file2 = new FileWriter("TiemposAuCl.txt",true); 
			bw2 = new BufferedWriter(file2);
			pw2 = new PrintWriter(bw2);
			file3 = new FileWriter("TiemposResp.txt",true); 
			bw3 = new BufferedWriter(file3);
			pw3 = new PrintWriter(bw3);
			
			algSim = "DES";
			algDig = "HMACSHA256";
			sock = new Socket("192.168.0.13", 8083);
			escritor = new PrintWriter(sock.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(
					sock.getInputStream()));
			comenzarComunicacion();
			pw1.close();
			pw2.close();
			pw3.close();
			bw1.close();
			bw2.close();
			bw3.close();
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
	}
	// cierre el socket y la entrada estándar

	public void comenzarComunicacion() throws Exception
	{
		escritor.println("HOLA");
		String respuesta = lector.readLine();
		if(respuesta.equals("OK"))
		{
			escritor.println("ALGORITMOS:"+algSim+":"+ALGORITMO_ASIM+":"+algDig);
			respuesta = lector.readLine();
			if(respuesta.equals("OK"))
			{

				String certHecho = generarCertificado();
				escritor.println("CERTCLNT:" + certHecho);
				String certRecibido = "";
				certRecibido=lector.readLine().split(":")[1] + "\n";
				while(!(respuesta=lector.readLine()).contains("END CERTIFICATE"))
				{
					certRecibido+= respuesta;
				}
				certRecibido+="\n" +respuesta;

				StringReader inPem = new StringReader(certRecibido);

				PEMParser pemPar = new PEMParser(inPem);
				X509CertificateHolder servCert = (X509CertificateHolder) pemPar.readObject();
				pemPar.close();
				pubKeyServer = new JcaX509CertificateConverter().getCertificate( servCert ).getPublicKey();

				reto();

				autenticar();

				transaccion();

			}
		}

	}

	public String generarCertificado() throws Exception {

		Date validityBeginDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		// in 2 years
		Date validityEndDate = new Date(System.currentTimeMillis() + 2 * 365 * 24 * 60 * 60 * 1000);

		// GENERATE THE PUBLIC/PRIVATE RSA KEY PAIR
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITMO_ASIM);
		keyPairGenerator.initialize(1024, new SecureRandom());

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// GENERATE THE X509 CERTIFICATE
		X509V3CertificateGenerator v3Cert = new X509V3CertificateGenerator();
		X500Principal dnName = new X500Principal("CN=JSM");

		v3Cert.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
		v3Cert.setSubjectDN(dnName);
		v3Cert.setIssuerDN(dnName); // use the same
		v3Cert.setNotBefore(validityBeginDate);
		v3Cert.setNotAfter(validityEndDate);
		v3Cert.setPublicKey(keyPair.getPublic());
		//si es HMACSHA1-->SHA1withRSA
		//si es HMACMD5-->MD5withRSA
		//si es HMACSHA256-->SHA256withRSA
		if(algDig.equals("HMACSHA256"))
		v3Cert.setSignatureAlgorithm("SHA256withRSA");
		else if(algDig.equals("HMACMD5"))
			v3Cert.setSignatureAlgorithm("MD5withRSA");
		else if(algDig.equals("HMACSHA1"))
			v3Cert.setSignatureAlgorithm("SHA1withRSA");

		X509Certificate cert = v3Cert.generate(keyPair.getPrivate());
		priKeyCliente = keyPair.getPrivate();
		StringWriter out = new StringWriter();
		PemWriter pem = new PemWriter(out);
		pem.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
		pem.flush();
		pem.close();
		out.close();
		String result = out.toString();
		return result;
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Security.addProvider(new BouncyCastleProvider());
		new Cliente();
	}

	/**
	 * Envío y confirmación del reto.
	 */
	public void reto() {
		try {
			Random rand = new Random();
			rand.setSeed(System.currentTimeMillis());
			int reto = (int) (rand.nextInt());
			while (!(String.valueOf(reto).length() % 2 == 0)) {
				//Hay que revisar que se le envíe al servidor una cadena 
				//de números con un número par de dígitos, como 01 o 4875 o 195723.
				reto = (int) (rand.nextInt()*10000+1);
			}
			
			String hexa = DatatypeConverter.printHexBinary(String.valueOf(reto).getBytes());
			///////////////////////////////
			Date a = new Date();
			
			escritor.println(hexa);
			String respuesta = "";
			respuesta = lector.readLine();
			respuesta = lector.readLine();

			byte[] retoRespuesta = DatatypeConverter.parseHexBinary(respuesta);
			respuesta = new String (retoRespuesta);

			Object Date;
			if(Integer.parseInt(respuesta)==reto)
			{
				escritor.println("OK");
			}
			else
			{
				
			}
			
			/////////////////////////////
			Date b = new Date ();
			pw1.println(b.getTime()-a.getTime());
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void autenticar() {
		try {
			String respuesta = lector.readLine();
			
			//////////////////////////////////////
			Date a = new Date();
			
			
			String autStr = "usuario,clave";
			
			escritor.println(autStr);

			respuesta = lector.readLine();
			
			////////////////////////////////////
			Date b = new Date();
			pw2.println(b.getTime() - a.getTime());
			
			if(!respuesta.equalsIgnoreCase("OK")) {
				throw new Exception("No se logro autenticar.");
			}

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void transaccion() {
		try {
			String cedula = "1072699444";

			String cipMes = cedula + ":" + cedula;
			
			escritor.println(cipMes);
			
			/////////////////////////////////////////////
			Date a = new Date();

			String respuesta = lector.readLine();
			
			////////////////////////////////////////////////
			Date b = new Date();
			pw3.println(b.getTime() - a.getTime());
			
			if(!respuesta.equalsIgnoreCase("OK")) {
				throw new Exception("No se logro transmitir.");
			}
			

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

}