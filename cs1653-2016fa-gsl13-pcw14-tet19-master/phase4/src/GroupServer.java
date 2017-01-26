/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

 //Note: Whenever and whereever UserList is being read or written to, read and write to GroupList.bin as well

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.nio.charset.*;
import java.security.*;
import java.util.Base64;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;		//added this to have a grouplist
	public Database database;
	public KeyDatabase keyDatabase;
	Socket sock = null;
	Crypto crypto = new Crypto();
	//constructor for group server if no port is given (default port = 8765)
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	//constructor for group server if port is given
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	//main method for running group server
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		String userFile = "UserList.bin";
		String groupFile = "GroupList.bin";		//added to have a file for grouplist
		String databaseFile = "Database.bin";	//added for database
		String keyFile = "KeyDatabase.bin";	//added for storing keys
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream = null;
		ObjectInputStream groupStream = null;
		ObjectInputStream databaseStream = null;
		ObjectInputStream keyStream = null;
    FileInputStream fis = null;
    FileInputStream gis = null;
		FileInputStream dis = null;
		FileInputStream kis = null;

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		//Open user file to get user list
		try
		{
			//read UserList.bin for its contents for userList
			fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();

			//Added for groups
			//read GroupList.bin for its contents for groupList
			gis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(gis);
			groupList = (GroupList)groupStream.readObject();

			//added for database
			//read Database.bin for its contents for database
			dis = new FileInputStream(databaseFile);
			databaseStream = new ObjectInputStream(dis);
			database = (Database)databaseStream.readObject();

			//added for keys
			//read KeyDatabse.bin for its contents for the key database
			kis = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(kis);
			keyDatabase = (KeyDatabase)keyStream.readObject();

			System.out.println("Successful read of UserList.bin, GroupList.bin, Database.bin, and KeyDatabase.bin");

			Key pubKey = database.getPublicKey();
			String keyString = new String(crypto.hashSHA_256(Base64.getEncoder().encodeToString(pubKey.getEncoded())), StandardCharsets.UTF_8);
			// System.out.println("Public key (hash): " + keyString);
			System.out.println("Public key(full): " + Utils.formatByteArray(pubKey.getEncoded()));

		}
		catch(FileNotFoundException e)
		{
			//Note: So, if userlist or grouplist is lost (one without the other) then very likely, the whole system won't work
				//it's better to create BOTH new lists once one is lost or missing
			System.out.println("UserList.bin, GroupList.bin, Database.bin, or Keydatabase.bin Does Not Exist. Creating new files...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Enter your password: ");		//take the password for database
			String password = console.next();

			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			System.out.println("Creating UserList.bin");
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");			//there's a group called ADMIN we have to create

			//do the same for groups
			System.out.println("Creating GroupList.bin");
			groupList = new GroupList();			//create new grouplist
			groupList.addGroup("ADMIN");		//create the ADMiN group
			groupList.addUserToGroup(username, "ADMIN");			//add user to the group
			groupList.setOwnership(username, "ADMIN");		//make them owner of ADMIN group

			//do the same for database
			System.out.println("Creating Database.bin");
			database = new Database();
			database.addItem(username, password);

			//do the same for key database
			System.out.println("Creating KeyDatabase.bin");
			keyDatabase = new KeyDatabase();
			keyDatabase.newKey("ADMIN");		//new group needs an AES key to start out with


			Key pubKey = database.getPublicKey();
			String keyString = new String(crypto.hashSHA_256(Base64.getEncoder().encodeToString(pubKey.getEncoded())), StandardCharsets.UTF_8);//crypto.hashSHA_256(Base64.getEncoder().encodeToString(pubKey.getEncoded())).toString();
			System.out.println("Public key (hash): " + keyString);
			System.out.println("Public key(full): " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList/GroupList/Database/KeyDatabase file");
      e.printStackTrace();
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList/GroupList/Database/KeyDatabase file");
      e.printStackTrace();
		}

    // Make sure all open streams are closed
    finally {
      try {
        if (userStream != null) userStream.close();
      } catch(IOException e){}
      try {
        if (groupStream != null) groupStream.close();
      } catch(IOException e){}
			try{
				if(databaseStream != null) databaseStream.close();
			} catch(IOException e){}
			try{
				if(keyStream != null) keyStream.close();
			}catch(IOException e){}
      try {
        if (fis != null) fis.close();
      } catch(IOException e){}
      try {
        if (gis != null) gis.close();
      } catch(IOException e){}
			try{
				if(dis != null) dis.close();
			} catch(IOException e){}
			try{
				if(kis != null) fis.close();
			} catch(IOException e){}
    }


		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		//This block listens for connections and creates threads on new connections
		 Scanner keyboard = new Scanner(System.in);
			try
			{

				final ServerSocket serverSock = new ServerSocket(port);

				GroupThread thread = null;
				while(true)
				{
					sock = serverSock.accept();
					thread = new GroupThread(sock, this);
					thread.start();
				}
			}
			catch(Exception e)
			{
				System.err.println("Error 1: " + e.getMessage());
				e.printStackTrace(System.err);
			}
	}

	public void stop() {
		try {

			sock.close();
		}
		catch (Exception e) {

		}
	}

}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;

	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		System.out.println("\nShutting down server");
		System.out.println("\nGoodBye :) Have a Nice Day!!!\n");
    ObjectOutputStream outStream = null;	//for UserList.bin
    ObjectOutputStream outStream2 = null;	//for GroupList.bin
		ObjectOutputStream outStream3 = null;	//for Database.bin
		ObjectOutputStream outStream4 = null;
		FileOutputStream fos1 = null;
		FileOutputStream fos2 = null;
		FileOutputStream fos3 = null;
		FileOutputStream fos4 = null;
		try
		{
			fos1 = new FileOutputStream("UserList.bin");
			outStream = new ObjectOutputStream(fos1);
			outStream.writeObject( my_gs.userList);
			System.out.println("Auto-saved UserList.bin");

			//added output stream for GroupList
			fos2 = new FileOutputStream("GroupList.bin");
			outStream2 = new ObjectOutputStream(fos2);
			outStream2.writeObject( my_gs.groupList);
			System.out.println("Auto-saved GroupList.bin");

			//added output stream for Database
			fos3 = new FileOutputStream("Database.bin");
			outStream3 = new ObjectOutputStream(fos3);
			outStream3.writeObject(my_gs.database);
			System.out.println("Auto-saved Database.bin");

			//added output stream for KeyDatabase
			fos4 = new FileOutputStream("KeyDatabase.bin");
			outStream4 = new ObjectOutputStream(fos4);
			outStream4.writeObject(my_gs.keyDatabase);
			System.out.println("Auto-saved KeyDatabase.bin");
		}
		catch(Exception e)
		{
			System.out.println("Error 2: " + e.getMessage());
			e.printStackTrace();

		}
    // Ensure streams are clsoed
    finally {
      try {
        if (outStream != null) outStream.close();
      } catch(IOException e){}
      //closing quietly}
      try {
        if (outStream2 != null) outStream2.close();
      }catch(IOException e){}
			try{
				if(outStream3 != null) outStream3.close();
			} catch(IOException e){}
			try{
				if(outStream4 != null) outStream4.close();
			} catch(IOException e){};
			try{
				if(fos1 != null) fos1.close();
			} catch(IOException e){}
			try{
				if(fos2!= null) fos2.close();
			} catch(IOException e){}
			try{
				if(fos3 != null) fos3.close();
			} catch(IOException e){}
			try{
				if(fos4 != null) fos4.close();
			} catch(IOException e){}
    }
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;

	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}

	public void run()
	{
		do
		{
			try
			{
				System.out.println("Autosaving group and user lists...");
				ObjectOutputStream outStream = null;
				ObjectOutputStream outStream2 = null;
				ObjectOutputStream outStream3 = null;	//for Database.bin
				ObjectOutputStream outStream4 = null;
				FileOutputStream fos1 = null;
				FileOutputStream fos2 = null;
				FileOutputStream fos3 = null;
				FileOutputStream fos4 = null;
				try
				{
					fos1 = new FileOutputStream("UserList.bin");
					outStream = new ObjectOutputStream(fos1);
					outStream.writeObject( my_gs.userList);
          System.out.println("Auto-saved UserList.bin");

					//added output stream for GroupList
					fos2 = new FileOutputStream("GroupList.bin");
					outStream2 = new ObjectOutputStream(fos2);
					outStream2.writeObject( my_gs.groupList);
          System.out.println("Auto-saved GroupList.bin");

					//added output stream for Database
					fos3 = new FileOutputStream("Database.bin");
					outStream3 = new ObjectOutputStream(fos3);
					outStream3.writeObject(my_gs.database);
					System.out.println("Auto-saved Database.bin");

					//added output stream for KeyDatabase
					fos4 = new FileOutputStream("KeyDatabase.bin");
					outStream4 = new ObjectOutputStream(fos4);
					outStream4.writeObject(my_gs.keyDatabase);
					System.out.println("Auto-saved KeyDatabase.bin");
				}
				catch(Exception e)
				{
          System.out.println("Autosave Interrupted");
					System.out.println("Error 3: " + e.getMessage());
					e.printStackTrace();
				}
        // Ensure streams are clsoed
        finally {
          try {
            if (outStream != null) outStream.close();
          } catch(IOException e){}
          try {
            if (outStream2 != null) outStream2.close();
          } catch(IOException e){}
					try{
						if(outStream3 != null) outStream3.close();
					} catch(IOException e){}
					try{
						if(outStream4 != null) outStream4.close();
					} catch(IOException e){}
					try{
						if(fos1 != null) fos1.close();
					} catch(IOException e){}
					try{
						if(fos2!= null) fos2.close();
					} catch(IOException e){}
					try{
						if(fos3 != null) fos3.close();
					} catch(IOException e){}
					try{
						if(fos4 != null) fos4.close();
					} catch(IOException e){}
        }
        Thread.sleep(300000); //should be 300000//Save group and user lists every 5 minutes
      }
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);

	}


}
