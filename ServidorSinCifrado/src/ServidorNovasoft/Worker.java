package ServidorNovasoft;

import java.awt.FontFormatException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import utils.Seguridad;
import utils.Transformacion;

/**
 * Esta clase implementa el protocolo que se realiza al recibir una conexión de
 * un cliente. 
 * Infraestructura Computacional 201720 
 * Universidad de los Andes.
 * 
 * @author Jairo Emilio Bautista
 * @author Mariana Rodriguez
 */
public class Worker {

	// ----------------------------------------------------
	// CONSTANTES DE CONTROL DE IMPRESION EN CONSOLA
	// ----------------------------------------------------
	public static final boolean SHOW_ERROR = true;
	public static final boolean SHOW_S_TRACE = true;
	public static final boolean SHOW_IN = true;
	public static final boolean SHOW_OUT = true;
	// ----------------------------------------------------
	// CONSTANTES PARA LA DEFINICION DEL PROTOCOLO
	// ----------------------------------------------------
	public static final String OK = "OK";
	public static final String ALGORITMOS = "ALGORITMOS";
	public static final String RC4 = "RC4";
	public static final String BLOWFISH = "Blowfish";
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String RSA = "RSA";
	public static final String HMACMD5 = "HMACMD5";
	public static final String HMACSHA1 = "HMACSHA1";
	public static final String HMACSHA256 = "HMACSHA256";
	public static final String CERTSRV = "CERTSRV";
	public static final String CERTCLNT = "CERTCLNT";
	public static final String SEPARADOR = ":";
	public static final String HOLA = "HOLA";
	public static final String ERROR = "ERROR";
	public static final String ERROR_FORMATO = "Error en el formato. Cerrando conexion";

	/**
	 * Metodo que se encarga de imprimir en consola todos los errores que se
	 * producen durante la ejecuación del protocolo. Ayuda a controlar de forma
	 * rapida el cambio entre imprimir y no imprimir este tipo de mensaje
	 */
	private static void printError(Exception e) {
		if (SHOW_ERROR) {
			System.out.println(e.getMessage());
		}
		if (SHOW_S_TRACE) {
			e.printStackTrace();
		}
	}

	/**
	 * Metodo que se encarga de leer los datos que envia el punto de atencion.
	 * Ayuda a controlar de forma rapida el cambio entre imprimir y no imprimir
	 * este tipo de mensaje
	 */
	private static String read(BufferedReader reader) throws IOException {
		String linea = reader.readLine();
		if (SHOW_IN) {
			System.out.println("<<CLNT: " + linea);
		}
		return linea;
	}

	/**
	 * Metodo que se encarga de escribir los datos que el servidor envia el
	 * punto de atencion. Ayuda a controlar de forma rapida el cambio entre
	 * imprimir y no imprimir este tipo de mensaje
	 */
	private static void write(PrintWriter writer, String msg) {
		writer.println(msg);
		if (SHOW_OUT) {
			System.out.println(">>SERV: " + msg);
		}
	}

	/**
	 * Metodo que establece el protocolo de comunicacion con el punto de
	 * atencion.
	 */

	public static void atenderCliente(Socket s) {
		try {
			PrintWriter writer = new PrintWriter(s.getOutputStream(), true);
			BufferedReader reader = new BufferedReader(new InputStreamReader(s.getInputStream()));
		
			// Recibe HOLA.
			// En caso de error de formato, cierra la conexion.

			String linea = read(reader);

			if (!linea.equals(HOLA)) {
				write(writer, ERROR_FORMATO);
				throw new FontFormatException(linea);
			}

			//////////////////////////////////////////////////////////////////
			// Envia el status del servidor y recibe los algoritmos de cifrado
			//////////////////////////////////////////////////////////////////
			write(writer, OK);
			linea = read(reader);
			if (!(linea.contains(SEPARADOR) && linea.split(SEPARADOR)[0].equals(ALGORITMOS))) {
				write(writer, ERROR_FORMATO);
				throw new FontFormatException(linea);
			}
			
			// Verificar los algoritmos enviados sean reconocidos y soportados
			String[] algoritmos = linea.split(SEPARADOR);

			// Comprueba que el algoritmo asimetrico sea simetrico y reconocido.
			if (!(algoritmos[1].equals(BLOWFISH) || algoritmos[1].equals(AES) || algoritmos[1].equals(DES)
					|| algoritmos[1].equals(RC4))) {
				write(writer,ERROR);
				throw new NoSuchAlgorithmException();
			}

			// Comprueba que el algoritmo asimetrico sea RSA.
			if (!algoritmos[2].equals(RSA)) {
				write(writer,ERROR);
				throw new NoSuchAlgorithmException();
			}
			// Comprueba que el algoritmo HMAC sea valido.
			if (!(algoritmos[3].equals(HMACMD5) || algoritmos[3].equals(HMACSHA1)
					|| algoritmos[3].equals(HMACSHA256))) {
				write(writer,ERROR);
				throw new NoSuchAlgorithmException();
			}

			// Confirmando al cliente que los algoritmos son soportados.
			write(writer, OK);

			// ////////////////////////////////////////////////////////////////////////
			// Recibiendo el certificado del cliente 
			// ////////////////////////////////////////////////////////////////////////

			X509Certificate certificadoCliente;
			// Se trata de reconstruir el certificado a partir de la info recibida
			try {
				linea = read(reader);

				//Verificar el formato de lo enviado
				String linea1 [] = linea.split(SEPARADOR);
				
				if(!linea1[0].equals(CERTCLNT))
				{
					write(writer, ERROR_FORMATO);
					throw new FontFormatException(linea);
				}
				
				String strToDecode = "";
				strToDecode += linea1[1]+"\n";
				linea=read(reader);
				while (!linea.equals("-----END CERTIFICATE-----")) {
					strToDecode += linea + "\n";
					linea = read(reader);
				}
				strToDecode += linea;
				System.out.println(strToDecode);
				StringReader rea = new StringReader(strToDecode);
				PemReader pr = new PemReader(rea);
				PemObject pemcertificadoPuntoAtencion = pr.readPemObject();
				X509CertificateHolder certHolder = new X509CertificateHolder(pemcertificadoPuntoAtencion.getContent());
				certificadoCliente = new JcaX509CertificateConverter().getCertificate(certHolder);
				pr.close();

			} catch (Exception e) {
				write(writer, ERROR);
				write(writer, e.getMessage());
				e.printStackTrace();
				throw new FontFormatException("Error en el certificado recibido, no se puede decodificar");
			}

			// ////////////////////////////////////////////////////////////////////////
			// Enviando el certificado del servidor
			// ////////////////////////////////////////////////////////////////////////
			
			//Se generan las llaves publica y privada del servidor
			KeyPair keyPair = Seguridad.generateRSAKeyPair();
			
			X509Certificate cert;
			try {
				Security.addProvider(new BouncyCastleProvider());
				KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA, "BC");
				keyGen.initialize(1024);
				keyPair = keyGen.generateKeyPair();
				cert = Seguridad.generateV3Certificate(keyPair);
				StringWriter wr = new StringWriter();
				JcaPEMWriter pemWriter = new JcaPEMWriter(wr);
				pemWriter.writeObject(cert);
				pemWriter.flush();
				pemWriter.close();
				String certStr = wr.toString();
				write(writer, CERTSRV+SEPARADOR+certStr);
			} catch (Exception e) {
				// Nunca va a pasar por acá, el certificado del servidor está bien
				e.printStackTrace();
			}

			// ////////////////////////////////////////////////////////////////////////
			// Reto 1
			///////////////////////////////////////////////////////////////////////////
			linea = read(reader);
			linea = read(reader);
			byte[] resReto1Bytes = Transformacion.decodificar(linea);
			String resReto1String = Transformacion.toHexString(resReto1Bytes);

			write(writer, resReto1String);

			linea = read(reader);
			if (!linea.equalsIgnoreCase("OK")) {
				write(writer, ERROR);
				throw new FontFormatException("Error, no se paso el reto 1.");
			}

			// ////////////////////////////////////////////////////////////////////////
			// Enviando llave simetrica 
			// ////////////////////////////////////////////////////////////////////////

			write(writer, "LLAVE");

			//////////////////////////////////////////////////////////////////////////
			//Recibe el usuario y la clave para autenticacion
			//////////////////////////////////////////////////////////////////////////
			linea = read(reader);

			// Confirmando al cliente que la autenticacion se realizo correctamente.
			write(writer, OK);

			// ////////////////////////////////////////////////////////////////////////
			// Recibe la consulta del cliente y su digest 
			// ////////////////////////////////////////////////////////////////////////

			linea = read(reader);
			write(writer, OK);
			
			
		} catch (NullPointerException e) {
			// Probablemente la conexion fue interrumpida.
			printError(e);
		} catch (IOException e) {
			// Error en la conexion con el cliente.
			printError(e);
		} catch (FontFormatException e) {
			// Si hubo errores en el protocolo por parte del cliente.
			printError(e);
		} catch (NoSuchAlgorithmException e) {
			// Si los algoritmos enviados no son soportados por el servidor.
			printError(e);
		} catch (IllegalStateException e) {
			// El certificado no se pudo generar.
			// No deberia alcanzarce en condiciones normales de ejecuci��n.
			printError(e);
		} // catch (CertificateNotYetValidException e) {
			// El certificado del cliente no se pudo recuperar.
			// El cliente deberia revisar la creacion y envio de su
			// certificado.
			// printError(e);
		// }
		catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				s.close();
			} catch (Exception e) {
				// DO NOTHING
			}
		}
	}

}
