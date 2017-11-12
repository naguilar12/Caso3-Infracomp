package infracomp;

import uniandes.gload.core.Task;

public class ClientServerTask extends Task{
	
	@Override
	public void execute() {
		new Cliente();
	}
	
	@Override
	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}
	
	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}

}
