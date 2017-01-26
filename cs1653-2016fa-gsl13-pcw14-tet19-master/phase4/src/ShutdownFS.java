import java.lang.NumberFormatException;
import java.util.*;


public class ShutdownFS {

	private static FileClient f_client = new FileClient();
  private static Scanner keyboard = new Scanner(System.in);

  public static void main(String[] args) {
		System.out.println("Please enter the address of the file server (leave blank for localhost):");
		String addressFS = keyboard.nextLine();
		if(addressFS.equals("")) addressFS = "localhost";

		System.out.println("Please enter a port for the file server if different from the default:");
		String port = keyboard.nextLine();
		int portFS;
		try {
				portFS = Integer.parseInt(port);
		}
		catch (NumberFormatException e){
			portFS = FileServer.SERVER_PORT;
		}

		if (f_client.connect(addressFS, portFS))
			f_client.shutdown();

		System.exit(0);
	}
}
