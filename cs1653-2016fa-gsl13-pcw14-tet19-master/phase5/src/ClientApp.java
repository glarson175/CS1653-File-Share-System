import java.io.*;
import java.lang.NumberFormatException;
import java.security.*;
import java.nio.charset.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

enum ServerType {
  FILE, GROUP
}



public class ClientApp {

  private static FileClient f_client = new FileClient();
  protected static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
	private static Crypto crypto = new Crypto();
  private static String username = "";
  private static UserToken token = null;
	private static PublicKey gsKey;
	protected static Key fsKey;
  private static KeyList keylist;
  private static String addressGS;
  private static int portGS;
  private static String addressFS;
  private static int portFS;





  public static void main(String[] args) {


    System.out.println("\nWelcome to the Client Application for our file sharing program!");
    System.out.println("---------------------------------------------------------------");
    System.out.println("---------------------------------------------------------------\n");
    // Read list of trusted public keys into memory
    keylist = readKeyList();

    System.out.println("\n--------------------CONNECT TO GROUP SERVER--------------------\n");

    // Get address from user and store in global variables addressGS and portGS
    getServerAddress(ServerType.GROUP);

    // connect to group server, retrieve its public key, and verify the key is trusted
    boolean connected = connectToServer(ServerType.GROUP);

    // if the connection failed, see if user wants to try again
    while (!connected) {
      if (g_client.isConnected()) g_client.disconnect();
      System.out.println("There was a problem with connecting to the group server. Do you want "
                          + "to try again? Enter 'y' for yes." );
      if (keyboard.nextLine().charAt(0)=='y') {
        System.out.println("Please enter the address information for the group server connection.");
        getServerAddress(ServerType.GROUP);
        connected = connectToServer(ServerType.GROUP);
      }
      else {
        System.out.println("Goodbye!");
        System.exit(-1);
      }
    }

    System.out.println("\n--------------------CONNECT TO FILE SERVER---------------------\n");

    // Get address from user and store in global variables addressFS and portFS
    getServerAddress(ServerType.FILE);

    // connect to file server
    connected = connectToServer(ServerType.FILE);

     // if the connection failed, see if user wants to try again
    while (!connected) {
      if (f_client.isConnected()) f_client.disconnect();
      System.out.println("There was a problem with connecting to the file server. Do you want "
                          + "to try again? Enter 'y' for yes." );
      if (keyboard.nextLine().charAt(0)=='y') {
        System.out.println("Please enter the address information for the file server connection.");
        connected = connectToServer(ServerType.FILE);
      }
      else {
        System.out.println("Goodbye!");
        System.exit(-1);
      }

    }


    // authenticate file server with file server public key and challenge and set up shared session key

    boolean trustedFS = authenticateFileServer();
    while (!trustedFS) {
      System.out.println("Warning! Untrusted File Server! Aborting connection.");
      f_client.disconnect();
      System.out.println("Do you want to connect to another file server? Enter 'y' for yes.");
      if (keyboard.nextLine().charAt(0)=='y') {
        System.out.println("Please enter the address information for the file server connection.");
        getServerAddress(ServerType.FILE);
        connected = connectToServer(ServerType.FILE);
        if (connected)
          trustedFS = authenticateFileServer();
      }
      else {
        System.out.println("Goodbye!");
        f_client.disconnect();
        g_client.disconnect();
        System.exit(-1);
      }

    }


    // authenticate user to group server with password

    do{
      System.out.print("\nPlease enter your username: ");
      username = keyboard.nextLine();
      System.out.print("Please enter your password: ");
      String password = keyboard.nextLine();

      // Run the authentication protocal between the server and client.

      token = g_client.authenticate(username, password);
      while (token == null) {
        System.out.println("Invalid username/password!");
        System.out.print("\nPlease enter your username: ");
        username = keyboard.nextLine();
        System.out.print("Please enter your password: ");
        password = keyboard.nextLine();
        token = g_client.authenticate(username, password);
      }

      // check that token signature is valid
      byte[] hashedToken = crypto.hashSHA_256(token.toString());
      byte[] signature = token.getSignature();
      System.out.println("Token has valid signature from group server: "
                          + crypto.verifyRSASig(hashedToken, signature, gsKey));

      if(token != null) break;
      //System.out.println("Invalid username/password combination.");
    } while(true);

    System.out.println("Received token from group server.");
    System.out.println(token);


    // Menu for interacting with servers

    String choice = "";
    while (!choice.equals("q")){
      choice = displayMenu();

      switch (choice){

        case "1":
          uploadFile();
          break;

        case "2":
          downloadFile();
          break;

        case "3":
          deleteFile();
          break;

        case "4":
          seeGroupFiles();
          break;

        case "5":
          createGroup();
          token = g_client.getToken(username);
          break;

        case "6":
          deleteGroup();
          token = g_client.getToken(username);
          break;

        case "7":
          addUserToGroup();
          token = g_client.getToken(username);
          break;

        case "8":
          deleteUserFromGroup();
          token = g_client.getToken(username);
          break;

        case "9":
          listMembers();
          break;

        case "10":
          createUser();
          break;

        case "11":
          deleteUser();
          token = g_client.getToken(username);
          break;

        case "12":
          token = g_client.getToken(username);
          System.out.println(token);
          break;

        case "13":
          changePassword();
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
    System.out.println("13. Change your password");
    System.out.print("Choose an action: ");
    choice = keyboard.nextLine();
    return choice;
  }

  public static void getServerAddress(ServerType type) {
    System.out.print("Server address (leave blank for localhost):");
    String address = keyboard.nextLine();
    if(address.equals("")) address = "localhost";

    if(type == ServerType.FILE)
      addressFS = address;
    else
      addressGS = address;

    System.out.print("Server port (leave blank for default):");
    String portStr = keyboard.nextLine();
    int port;
    try {
        port = Integer.parseInt(portStr);
        if (type == ServerType.FILE)
          portFS = port;
        else
          portGS = port;
    }
    catch (NumberFormatException e){
      if (type == ServerType.FILE)
        portFS = FileServer.SERVER_PORT;
      else
        portGS = GroupServer.SERVER_PORT;
    }
  }

  public static boolean connectToServer(ServerType type){

    boolean trusted = false;
    Client client = null;
    String address;
    int port;
    Key key = null;

    if (type == ServerType.GROUP){
      client = g_client;
      address = addressGS;
      port = portGS;
      if (client.connect(address, port)){
        //Get the GroupServer's public key
        gsKey = g_client.getGSKey();
        if(gsKey != null){
          System.out.println("Successfully received group server's key!!");
          key = (Key)gsKey;
        }
        else{
          System.out.println("From Client: Problem retrieving group server's key.");
          client.disconnect();
        }
      }
      else {
        System.out.println("Problem connecting to group server!");
      }
    }

    else {
      client = f_client;
      address = addressFS;
      port = portFS;
      if (client.connect(address, port)){
        //Get the FileServer's public key
        key = f_client.getFSKey();
        if(key != null){
          System.out.println("Successfully received file server's key!!");
          fsKey = key;
        }
        else{
          System.out.println("From Client: Problem retrieving file server's key.");
          client.disconnect();
        }
      }
      else {
        System.out.println("Problem connecting to file server!");
      }
    }

    // Check if key is in trusted key list
    if (!(keylist.isEmpty())) {
     trusted = keylist.isTrustedKey(address, port, key);
    }
    if (!trusted){
      System.out.println("Verify Public Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
      System.out.println("Do you trust this key? (y/n)");
      String trustKey = keyboard.next();
      if(!trustKey.equals("y")){
        System.out.println("Aborting connection with untrusted " + type + " Server.");
        client.disconnect();
      }

      keylist.addKey(address, port, key);
      saveKeyList();
      keyboard.nextLine();
      System.out.println();
      trusted = true;
    }
    else {
      System.out.println("Address:Key has previously been saved as trusted.");
    }

    return trusted;

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
      //T6: need key and versionNum
      int keyIndex = (g_client.fileKeys.get(group).size() - 1);
      System.out.println("Trying to upload to group: " + group + ". You will need key verion " + keyIndex);
      FileKeyPair kp = g_client.fileKeys.get(group).get(keyIndex);
      System.out.println("FileKeyPair being used for encryption: " + kp.toString() );

      // Upload method returns true if successful
      if (f.exists() && f_client.upload(source, dest, group, token, keyIndex, kp) )
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
    System.out.println("Enter group file is from:");
    String groupname = keyboard.nextLine();
    if (fileName.length() == 0 || dest.length() == 0)
      System.out.println("Invalid input. Please start operation again.");
    else {
      if (f_client.download(fileName, dest, token, groupname))
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

  //Phase 5: Change password
  public static void changePassword(){
    System.out.println("Enter current password:");
    String currentPass = keyboard.nextLine();
    System.out.println("Enter new password:");
    String newPass = keyboard.nextLine();
    if(g_client.changePassword(currentPass, newPass, token)){
      System.out.println("Successfully changed password.'");
    }
    else{
      System.out.println("Unsuccessful in changing password.");
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
      System.out.println("Successfully read from trusted key list.");
    }
    catch (FileNotFoundException e) {
      keylist = new KeyList();
      System.out.println("No trusted keys found. Creating new key list...");
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
      System.out.println("Saved key to TrustedKeys.bin");
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
      // client authentication happens with request when token is sent
      trusted = f_client.authenticate();
    }
    catch (IOException e){};
    return trusted;

  }
}
