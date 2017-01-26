import java.lang.NumberFormatException;
import java.util.*;


public class ShutdownGS {

  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);

  public static void main(String[] args) {

    System.out.println("Please enter the address of the group server (leave blank for localhost):");
    String addressGS = keyboard.nextLine();
    if(addressGS.equals("")) addressGS = "localhost";
    System.out.println("Please enter the port for the group server if different from default:");
    String port = keyboard.nextLine();
    int portGS;
    try{
        portGS = Integer.parseInt(port);
    }

    catch (NumberFormatException e){
      portGS = GroupServer.SERVER_PORT;
    }

		if (g_client.connect(addressGS, portGS))
			g_client.shutdown();

		System.exit(0);
	}
}
