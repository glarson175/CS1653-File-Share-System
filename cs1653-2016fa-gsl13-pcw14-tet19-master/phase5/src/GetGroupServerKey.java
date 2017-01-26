import java.io.*;
import java.lang.NumberFormatException;
import java.security.*;
import java.nio.charset.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class GetGroupServerKey {

  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
	private static Crypto crypto = new Crypto();
	private static PublicKey gsKey;

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

    if (g_client.connect(addressGS, portGS)){
      //Get the GroupServer's public key
      gsKey = g_client.getGSKey();
      if(gsKey != null){
        System.out.println("Successfully received group server's key!!");
      }
      else{
        System.out.println("Problem retriveing group server's key.");
        System.exit(0);
      }
      // Check if key is in trusted key list
      System.out.println("Verify Public Key: " + Base64.getEncoder().encodeToString(gsKey.getEncoded()));
      System.out.println("Do you trust this key? (y/n)");
      String trustKey = keyboard.next();
      if(!trustKey.equals("y")){
        System.out.println("Aborting connection with untrusted Group Server.");
        g_client.disconnect();
        System.exit(0);
      }
      System.out.println();
    }
    else{
        System.out.println("Problem connecting to group server");
    }
    g_client.exportPublicKey();
    System.out.println("Saved key to GSPublicKey.config");
    g_client.disconnect();
    System.exit(0);
  }
}
