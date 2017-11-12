package infracomp;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	/**
	 * Load Generator Service (From GLoad 1.3)
	 */
	private LoadGenerator generator;
	
	/**
	 * Construye un nuevo Generador.
	 */
	public Generator() {
		Task work = createTask();
		int numberOfTasks = 80;
		int gapBetweenTasks = 100;
		generator = new LoadGenerator("Client - Server Load Test", numberOfTasks, work, gapBetweenTasks);
		generator.generate();
	}
	
	/**
	 * Método auxiliar que construye una tarea.
	 * @return La tarea.
	 */
	private Task createTask() {
		return new ClientServerTask();
	}
	
	public static void main(String ... args) {
		@SuppressWarnings("unused")
		Generator gen = new Generator();
	}

}
