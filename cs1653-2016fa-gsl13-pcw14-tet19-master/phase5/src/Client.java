import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.UnknownHostException;
import java.io.IOException;


public abstract class Client {

	/* protected keyword is like private but subclasses have access
	 * Socket and input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {

		//System.out.println("Attempting to connect to " + server + ": " + port);
		try {
			sock = new Socket(server, port);
			//System.out.println("Connected!");
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			return true;
		}
		catch (UnknownHostException e){
			System.err.println("Error 1: " + e.getMessage());
			//e.printStackTrace(System.err);
			return false;
		}
		catch (IOException e){
			System.err.println("Error 2: " + e.getMessage());
			//e.printStackTrace(System.err);
			return false;
		}

	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		}
		else {
			return true;
		}
	}

	public void disconnect()	 {
		if (isConnected()) {
			try
			{
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
				if(!sock.isClosed())sock.close();
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
