import java.io.*;
import java.lang.NumberFormatException;
import java.security.*;
import java.nio.charset.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


public class ClientApp {

  private static FileClient f_client = new FileClient();
  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
	private static Crypto crypto = new Crypto();
  private static String username = "";
  private static UserToken token = null;
	private static PublicKey gsKey;
	private static Key fsKey;
  private static KeyList keylist;



  public static void main(String[] args) {

    keylist = readKeyList();

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

    boolean trusted = false;
    if (g_client.connect(addressGS, portGS)){
      //Get the GroupServer's public key
      gsKey = g_client.getGSKey();
      if(gsKey != null){
        System.out.println("Successfully received group server's key!!");
      }
      else{
        System.out.println("From Client: Problem retriveing group server's key.");
      }
      // Check if key is in trusted key list
      if (!(keylist.isEmpty())) {
       trusted = keylist.isTrustedKey(addressGS, portGS, gsKey);
      }
      if (!trusted){
        System.out.println("Verify Public Key: " + Base64.getEncoder().encodeToString(gsKey.getEncoded()));
        System.out.println("Do you trust this key? (y/n)");
        String trustKey = keyboard.next();
        if(!trustKey.equals("y")){
          System.out.println("Aborting connection with untrusted Group Server.");
          g_client.disconnect();
          f_client.disconnect();
          System.exit(0);
        }
        keylist.addKey(addressGS, portGS, gsKey);
        saveKeyList();
        keyboard.nextLine();
        System.out.println();
      }
      else {
        System.out.println("Address:Key has previously been saved as trusted.");
      }
      do{
        System.out.print("\nPlease enter your username: ");
        username = keyboard.nextLine();
        System.out.print("Please enter your password: ");
        String password = keyboard.nextLine();
        token = g_client.authenticate(username, password);
        byte[] hashedToken = crypto.hashSHA_256(token.toString());
        byte[] signature = token.getSignature();
        System.out.println("Token has valid signature from group server: " + crypto.verifyRSASig(hashedToken, signature, gsKey));
        //System.out.println(token.toString());
        if(token != null) break;
        //System.out.println("Invalid username/password combination.");
      } while(true);
      System.out.println("Received token from group server.");
      System.out.println(token);
    }
    else
      System.out.println("Problem connecting to group server");



    if (f_client.connect(addressFS, portFS)){

      // Get File Server Public Key
      fsKey = f_client.getFSKey();
      if(fsKey != null){
        System.out.println("Successfully received file server's key!!");
      }
      else{
        System.out.println("From Client: Problem retrieving file server's key.");
      }
      //Check to see if key is trusted
      if (!(keylist.isEmpty())) {
        trusted = keylist.isTrustedKey(addressFS, portFS, fsKey);
      }
      if (!trusted){
        System.out.println("Verify Public Key: " + Base64.getEncoder().encodeToString(fsKey.getEncoded()));
        System.out.println("Do you trust this key? (y/n)");
        String trustKey = keyboard.next();
        if(!trustKey.equals("y")){
          System.out.println("Aborting connection with untrusted File Server.");
          g_client.disconnect();
          f_client.disconnect();
          System.exit(0);
        }
        keylist.addKey(addressFS, portFS, fsKey);
        saveKeyList();
        keyboard.nextLine();
        System.out.println();
      }
      else {
        System.out.println("Address:Key has previously been saved as trusted.");
      }

      boolean trustedFS = authenticateFileServer();
      System.out.println("FS trusted " + trustedFS);
    }
    else
      System.out.println("Problem connecting to file server");

    String choice = "";
    while (!choice.equals("q")){
      choice = displayMenu();

      switch (choice){

        case "1":
          token = g_client.getToken(username);
          uploadFile();
          break;

        case "2":
          token = g_client.getToken(username);
          downloadFile();
          break;

        case "3":
          token = g_client.getToken(username);
          deleteFile();
          break;

        case "4":
          token = g_client.getToken(username);
          seeGroupFiles();
          break;

        case "5":
          token = g_client.getToken(username);
          createGroup();
          break;

        case "6":
          token = g_client.getToken(username);
          deleteGroup();
          break;

        case "7":
          token = g_client.getToken(username);
          addUserToGroup();
          break;

        case "8":
          token = g_client.getToken(username);
          deleteUserFromGroup();
          break;

        case "9":
          token = g_client.getToken(username);
          listMembers();
          break;

        case "10":
          token = g_client.getToken(username);
          createUser();
          break;

        case "11":
          token = g_client.getToken(username);
          deleteUser();
          break;

        case "12":
          token = g_client.getToken(username);
          System.out.println(token);
          break;

        case "13":
          g_client.exportPublicKey();
          break;

        case "q":
          System.out.println("Goodbye!");
          break;

        default:
            System.out.println("Invalid input. Try again.");
            break;
      }
    }

    g_client.disconnect();
    f_client.disconnect();
  System.exit(0);

  }


  public static String displayMenu(){

    System.out.println();
    System.out.println();
    String choice = "";
    System.out.println("Please choose a number from the menu, or type 'q' to quit.");
    System.out.println("1. Upload File");
    System.out.println("2. Download File");
    System.out.println("3. Delete File");
    System.out.println("4. List Files");
    System.out.println("5. Create group");
    System.out.println("6. Delete group");
    System.out.println("7. Add user to group");
    System.out.println("8. Delete user from group");
    System.out.println("9. List members of group");
    System.out.println("10. Create user (Admin-only)");
    System.out.println("11. Delete user (Admin-only)");
    System.out.println("12. Print your token");
    System.out.print("Choose an action: ");
    choice = keyboard.nextLine();
    return choice;
  }




  public static void uploadFile(){
    // Get user input
    System.out.println("Enter file to be uploaded:");
    String source = keyboard.nextLine();
    System.out.println("Enter name to give file on server:");
    String dest = keyboard.nextLine();
    System.out.println("Name of group to share file with: ");
    String group = keyboard.nextLine();
    if (source.length() == 0 || dest.length() == 0 || group.length() ==0)
      System.out.println("Invalid input. Please start operation again.");
    else {
      ShareFile file = new ShareFile(username, group, source);
      File f = new File(source);
      // Upload method returns true if successful
      if (f.exists() && f_client.upload(source, dest, group, token) )
        System.out.println("File Uploaded Successfully!");
      else
        System.out.println("Failed to upload file.");
    }
  }

  public static void downloadFile(){
    System.out.println("Enter name of file to download:");
    String fileName = keyboard.nextLine();
    System.out.println("Enter destination");
    String dest = keyboard.nextLine();
    if (fileName.length() == 0 || dest.length() == 0)
      System.out.println("Invalid input. Please start operation again.");
    else {
      if (f_client.download(fileName, dest, token))
        System.out.println("Download successful!");
      else
        System.out.println("Download NOT successful");
    }
  }

  public static void deleteFile(){
    System.out.println("Enter name of file to delete:");
    String fileName = keyboard.nextLine();
    if (fileName.length() == 0)
      System.out.println("Empty filename. Please start operation again.");
    else{
      if (f_client.delete(fileName, token))
        System.out.println("Successfully Deleted!");
      else
        System.out.println("Deletion NOT successful.");
    }
  }

  public static void seeGroupFiles(){
    /*System.out.println("What group do you want to see the files for");
      String groupname = keyboard.nextLine();*/
      List<String> files = f_client.listFiles(token);
      if (files != null){
        System.out.println(files.toString());
      }
  }

  public static void createGroup(){
    System.out.println("Enter name of group to create: ");
    String groupName = keyboard.nextLine();
  //  System.out.println(token.getSubject());
    if (g_client.createGroup(groupName, token))
      System.out.println("Group successfully created.");
    else {
      System.out.println("Group was NOT successfully created.");
    }


  }

  public static void deleteGroup(){
    System.out.println("Enter name of group to delete: ");
    String groupName = keyboard.nextLine();
    if(g_client.deleteGroup(groupName, token)){
      System.out.println("Group successfully deleted.");
      //token = g_client.getToken(username);
    }
    else{
      System.out.println("Group was NOT successfully deleted.");
    }
  }

  public static void addUserToGroup(){
    System.out.println("Enter name of user to add:");
    String name = keyboard.nextLine();
    System.out.println("Enter group name:");
    String groupName = keyboard.nextLine();

    if (g_client.addUserToGroup(name, groupName, token)){
      System.out.println("Successfully added to group!");
    }
    else {
      System.out.println("Error adding user to group");
    }
  }

  public static void deleteUserFromGroup(){
      System.out.println("Enter name of user to delete: ");
      String name = keyboard.nextLine();
      System.out.println("Enter group name: ");
      String groupName = keyboard.nextLine();

      if(g_client.deleteUserFromGroup(name, groupName, token)){
        System.out.println("Successfully deleted user from group");
      }
      else{
        System.out.println("Error removing user from group");
      }
  }

  public static void listMembers(){
    System.out.println("What group do you want to see the members of?");
    String groupname = keyboard.nextLine();
    List<String> members = g_client.listMembers(groupname, token);
    if (members != null)
      System.out.println(members.toString());
  }

  public static void createUser(){
    System.out.println("Enter name of user to create: ");
    String name = keyboard.nextLine();
		System.out.println("Enter password for user:");
		String password = keyboard.nextLine();
    if (g_client.createUser(name, password, token))
      System.out.println("Successfully created user " + name + ".");
    else {
      System.out.println("Unsuccessful in creation of user.");
    }

  }

  public static void deleteUser(){
      System.out.println("Enter name of user to delete: ");
      String name = keyboard.nextLine();
      if(g_client.deleteUser(name,token)){
        System.out.println("Successfully deleted user " + name + ".");
      }
      else {
        System.out.println("Unsuccessful in deletion of user.");
      }
  }


  public static void saveKeyToFile(Key k, String address, int port) {
    ObjectOutputStream outStream = null;
    FileOutputStream fos = null;
    try
    {
      fos = new FileOutputStream("TrustedKeys.bin");
      outStream = new ObjectOutputStream(fos);
      outStream.writeObject(address);
      outStream.writeObject(port);
      outStream.writeObject(k);
      System.out.println("Successfully wrote to TrustedKeys.bin");
    }
    catch(Exception e)
    {
      System.out.println("Error Saving key to file " + e.getMessage());
      e.printStackTrace();
    }
    // Ensure streams are clsoed
    finally {
      try { if (outStream != null) outStream.close();
      } catch(IOException e){}
      try { if (fos!= null) fos.close();
      } catch (IOException e){}
    }
  }

  public static KeyList readKeyList() {
    ObjectInputStream fileStream = null;
    FileInputStream fis = null;
    try
    {
      fis = new FileInputStream("TrustedKeys.bin");
      fileStream = new ObjectInputStream(fis);
      keylist = (KeyList)fileStream.readObject();
      System.out.println("Read key list");
    }
    catch (FileNotFoundException e) {
      keylist = new KeyList();
      System.out.println("Creating new key list");
    }
    catch (Exception e) {
      System.out.println("Problem reading from TrustedKeys.bin");
      e.printStackTrace();
    }
    finally {
      if (fis != null){
        try { fis.close(); }
        catch (IOException e) {}
      }
      if (fileStream != null) {
        try {fileStream.close();}
        catch (IOException e) {}
      }
    }
    return keylist;
  }

  public static void saveKeyList() {
    ObjectOutputStream outStream = null;
    try  {
      outStream = new ObjectOutputStream(new FileOutputStream("TrustedKeys.bin"));
      outStream.writeObject(keylist);
      System.out.println("Saved TrustedKeys.bin");
    }
    catch (Exception e) {
      System.out.println("Problem writing to TrustedKeys.bin");
      e.printStackTrace();
    }
    finally {
      try {outStream.close();}
      catch (IOException e) {};
    }
  }

  public static boolean authenticateFileServer() {
    boolean trusted = false;
    try{
      // this only authenticates the server, not the client.
      // client authentication happens with requets
      trusted = f_client.authenticate();

    }
    catch (IOException e){};
    return trusted;

  }
}
