package ServidorNovasoft;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.Security;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Esta clase implementa el servidor que atiende a los clientes. El servidor 
 * esta implemntado como un pool de threads. Cada vez que un cliente crea
 * una conexion al servidor, un thread se encarga de atenderlo el tiempo que
 * dure la sesion. 
 * Infraestructura Computacional 201720
 * Universidad de los Andes.
 * @author Jairo Emilio Bautista
 * @author Mariana Rodriguez
 */
public class Servidor implements Runnable {

	public static int clientesAtendidos = 0;
	/**
	 * Constante que especifica el tiempo maximo en milisegundos que se
	 * esperara por la respuesta de un cliente en cada una de las partes de la
	 * comunicacion
	 */
	private static final int TIME_OUT = 50000;

	/**
	 * Constante que especifica el numero de threads que se usan en el pool de
	 * conexiones.
	 */
	public static final int N_THREADS = 16;

	/**
	 * El socket que permite recibir requerimientos por parte de clientes.
	 */
	private static ServerSocket socket;

	/**
	 * El id del Thread
	 */
	private int id;

	/**
	 * Metodo main del servidor con seguridad que inicializa un pool de threads
	 * determinado por la constante nThreads.
	 * 
	 * @param args
	 *            Los argumentos del metodo main (vacios para este ejemplo).
	 * @throws IOException
	 *             Si el socket no pudo ser creado.
	 */
	public static void main(String[] args) throws IOException {

		// Adiciona la libreria como un proveedor de seguridad.
		// Necesario para crear llaves.
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		// Crea el socket que escucha en el puerto seleccionado.
		System.out.println("Indique el puerto del servidor: ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		int puerto = Integer.parseInt(br.readLine());
		socket = new ServerSocket(puerto);

		ExecutorService executor = Executors.newFixedThreadPool(N_THREADS);

		for (int i = 0; i < N_THREADS; i++) {
			Runnable worker = new Servidor(i);
			executor.execute(worker);
		}
		
		System.out.println("El servidor esta listo para aceptar conexiones.");

		executor.shutdown();

		while (!executor.isTerminated()) {

		}
		
		//////////////////////////////
		System.out.println("4. " + clientesAtendidos);
		
		System.out.println("Finished all threads");
	}

	/**
	 * Metodo que inicializa un thread y lo pone a correr.
	 * @param socket El socket por el cual llegan las conexiones.
	 * @throws SocketException si hay problemas con el manejo del socket
	 */
	public Servidor(int id) throws SocketException {
		this.id = id;
	}

	/**
	 * Metodo que atiende a los usuarios.
	 */
	@Override
	public void run() {
		while (true) {
			Socket s = null;
			
			// Recibe una conexion del socket.

			try {
				s = socket.accept();
				s.setSoTimeout(TIME_OUT);
			} catch (IOException e) {
				e.printStackTrace();
				continue;
			} catch (Exception e) {
				// Si hubo algun error creando la instancia del socket.
				// No deberia alcanzarse en condiciones normales de ejecucion.
				e.printStackTrace();
				continue;
			}
			System.out.println("Thread " + id + " recibe a un cliente.");
			Worker.atenderCliente(s);
			
			/////////////////////////////
			clientesAtendidos++;
			System.out.println("4. Se han atendido: " + clientesAtendidos);
		}
	}
}
