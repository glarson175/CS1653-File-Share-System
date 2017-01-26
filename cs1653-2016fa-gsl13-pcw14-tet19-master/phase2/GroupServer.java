/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */
 
 //Note: Whenever and whereever UserList is being read or written to, read and write to GroupList.bin as well

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;


public class GroupServer extends Server {
	
	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;		//added this to have a grouplist
    
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
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		//Open user file to get user list
		try
		{
			//read UserList.bin for its contents for userList
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			
			//Added for groups
			//read GroupList.bin for its contents for groupList
			FileInputStream gis = new FileInputStream(groupFile);
			groupStream = new ObjectInputStream(gis);
			groupList = (GroupList)groupStream.readObject();
			
			System.out.println("Successful read of FileList.bin and GroupList.bin.");
		}
		catch(FileNotFoundException e)
		{
			//Note: So, if userlist or grouplist is lost (one without the other) then very likely, the whole system won't work
				//it's better to create BOTH new lists once one is lost or missing
			System.out.println("UserList.bin or GroupList.bin Does Not Exist. Creating new files...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			System.out.println("Creating UserList.bin");
			userList = new UserList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			
			//looks like there's a group called ADMIN we have to create
			
			//do the same for groups
			System.out.println("Creating GroupList.bin");
			groupList = new GroupList();			//create new grouplist
			groupList.addGroup("ADMIN");		//create the ADMiN group
			groupList.addUserToGroup(username, "ADMIN");			//add user to the group
			groupList.setOwnership(username, "ADMIN");		//make them owner of ADMIN group
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList /GroupList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList /GroupList file");
			System.exit(-1);
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		//This block listens for connections and creates threads on new connections
		try
		{
			
			final ServerSocket serverSock = new ServerSocket(port);
			
			Socket sock = null;
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
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		ObjectOutputStream outStream2;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
			
			//added output stream for GroupList
			outStream2 = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
			outStream2.writeObject(my_gs.groupList);
		}
		catch(Exception e)
		{
			System.err.println("Error 2: " + e.getMessage());
			e.printStackTrace(System.err);
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
				//Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosaving group and user lists...");
				ObjectOutputStream outStream;
				ObjectOutputStream outStream2;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
					
					//added output stream for GroupList
					outStream2 = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
					outStream2.writeObject(my_gs.groupList);
					Thread.sleep(300000); //Save group and user lists every 5 minutes
					//Thread.sleep was moved here to just run a save first incase something happens
				}
				catch(Exception e)
				{
					System.err.println("Error 3: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
