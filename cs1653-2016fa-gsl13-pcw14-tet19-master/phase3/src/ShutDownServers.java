import java.io.*;
import java.lang.NumberFormatException;
import java.security.*;
import java.nio.charset.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class ShutDownServers{
	private static FileClient f_client = new FileClient();
  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
	private static Crypto crypto = new Crypto();
	private static PublicKey gsKey;
	private static Key fsKey;
  private static KeyList keylist;
	
  public static void main(String[] args) {

    //keylist = readKeyList();

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

    System.out.println("Please enter the address of the group server (leave blank for localhost):");
    String addressGS = keyboard.nextLine();
    if(addressGS.equals("")) addressGS = "localhost";
    System.out.println("Please enter the port for the group server if different from default:");
    port = keyboard.nextLine();
    int portGS;
    try{
        portGS = Integer.parseInt(port);
    }

    catch (NumberFormatException e){
      portGS = GroupServer.SERVER_PORT;
    }
		
		if (g_client.connect(addressGS, portGS)){
			System.out.println("gs connected");
		}
		if (f_client.connect(addressFS, portFS)){
			System.out.println("fs connected");
		}
		System.out.println("I JUST FUCKED YO SHIT!");
		shutdown(g_client, f_client);

    System.exit(0);
	}
	public static void shutdown(GroupClient gc, FileClient fc)
	{
		g_client.shutdown();
		f_client.shutdown();
		
	}
}
