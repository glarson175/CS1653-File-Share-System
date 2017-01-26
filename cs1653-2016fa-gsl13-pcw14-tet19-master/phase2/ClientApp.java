import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.lang.NumberFormatException;


public class ClientApp {

  private static FileClient f_client = new FileClient();
  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
  private static String username = "";
  private static UserToken token = null;


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
    
    f_client.connect(addressFS, portFS);
    g_client.connect(addressGS, portGS);
    
    do{
      System.out.println("Please enter your username: ");
      username = keyboard.nextLine();
      token = g_client.getToken(username);
      if(token != null) break;
      System.out.println("User does not exist.");
    }while(true);
    


  //  test1(username);
    String choice = "";
    while (!choice.equals("q")){
      choice = displayMenu();

      switch (choice){

        case "1":
          uploadFile();
          f_client.disconnect();
          f_client.connect(addressFS, portFS);
          break;

        case "2":
          downloadFile();
          break;

        case "3":
          deleteFile();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "4":
          seeGroupFiles();
          break;

        case "5":
          createGroup();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          token = g_client.getToken(username);
          break;

        case "6":
          deleteGroup();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "7":
          addUserToGroup();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "8":
          deleteUserFromGroup();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "9":
          listMembers();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "10":
          createUser();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;

        case "11":
          deleteUser();
          g_client.disconnect();
          g_client.connect(addressGS, portGS);
          break;
        /* Testing ONLY
        case "12":
          listEverything();
          break;
          */
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
    UserToken token = g_client.getToken(username);
    ShareFile file = new ShareFile(username, group, source);
    // Upload method returns true if successful
    if (f_client.upload(source, dest, group, token))
      System.out.println("File Uploaded Successfully!");
   else {
     System.out.println("Failed to upload file.");
   }

  }

  public static void downloadFile(){
    System.out.println("Enter name of file to download:");
    String fileName = keyboard.nextLine();
    System.out.println("Enter destination");
    String dest = keyboard.nextLine();
    if (f_client.download(fileName, dest, token))
      System.out.println("Download successful!");
    else
      System.out.println("Download NOT successful");

  }

  public static void deleteFile(){
    System.out.println("Enter name of file to delete:");
    String fileName = keyboard.nextLine();
    if (f_client.delete(fileName, token))
      System.out.println("Successfully Deleted!");
    else
      System.out.println("Deletion NOT successful.");
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
    if (g_client.createUser(name, token))
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
        System.out.println("Unsuccessful in deleteion of user.");
      }
  }

  /*
  //for testing ONLY
  public static void listEverything(){
    g_client.getAllLists(token);
  }
  
  
  //just for testing
  public static void test1(String username){
    ArrayList<String>groups = new ArrayList<String>();
    groups.add("1");
    UserToken token = new Token("test", username, groups);
    ShareFile file = new ShareFile(username, "1", "newfile.txt");
    f_client.upload("newfile.txt", "newfile2.txt", "1", token);
  }

  // just for testing purposes
  public static UserToken getDummyToken(){
    ArrayList<String>groups = new ArrayList<String>();
    groups.add("1");
    UserToken token = new Token("testIssuer", username, groups);
    return token;
  }
  */
}
