// 
// Decompiled by Procyon v0.5.30
// 

package ServidorNovasoft;

import java.net.Socket;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.net.ServerSocket;

public class Servidor implements Runnable
{
    private static ServerSocket a;
    private int b;
    
    public static void main(final String[] array) {
        Security.addProvider((Provider)new BouncyCastleProvider());
        System.out.println("Indique el puerto del servidor: ");
        Servidor.a = new ServerSocket(Integer.parseInt(new BufferedReader(new InputStreamReader(System.in)).readLine()));
        final ExecutorService fixedThreadPool = Executors.newFixedThreadPool(16);
        for (int i = 0; i < 16; ++i) {
            fixedThreadPool.execute(new Servidor(i));
        }
        System.out.println("El servidor esta listo para aceptar conexiones.");
        fixedThreadPool.shutdown();
        while (!fixedThreadPool.isTerminated()) {}
        System.out.println("Finished all threads");
    }
    
    public Servidor(final int b) {
        this.b = b;
    }
    
    @Override
    public void run() {
        while (true) {
            Socket accept;
            try {
                accept = Servidor.a.accept();
                accept.setSoTimeout(50000);
            }
            catch (IOException ex) {
                ex.printStackTrace();
                continue;
            }
            catch (Exception ex2) {
                ex2.printStackTrace();
                continue;
            }
            System.out.println("Thread " + this.b + " recibe a un cliente.");
            Worker.a(accept);
        }
    }
}
