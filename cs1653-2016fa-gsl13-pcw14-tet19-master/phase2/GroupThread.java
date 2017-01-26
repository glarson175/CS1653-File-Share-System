/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;

public class GroupThread extends Thread
{
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
	}

	public void run()
	{
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do
			{
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if(message.getMessage().equals("GET"))//Client wants a token
				{
					String username = (String)message.getObjContents().get(0); //Get the username
					if(username == null)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
					else
					{
						UserToken yourToken = createToken(username); //Create a token

						//Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(createUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{

					if(message.getObjContents().size() < 2)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

								if(deleteUser(username, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}

					output.writeObject(response);
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
				    /* Added for Phase 2*/
					if(message.getObjContents().size()<2){
						response = new Envelope("FAIL");
					}
					else{
						boolean success = false;
						if(message.getObjContents().get(0)!=null && message.getObjContents().get(1)!=null){
							//extract groupname
							String groupname = (String)message.getObjContents().get(0);
							//extract token
							UserToken token = (UserToken)message.getObjContents().get(1);
							//create group will return true or false depending on success of creating group
							success = createGroup(groupname, token);
						}
						if(success) {
							response = new Envelope("OK");
						}
						else{
							response = new Envelope("FAIL");
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				     /* Added for Phase 2*/
					if(message.getObjContents().size()<2){
						response = new Envelope("FAIL");
					}
					else{
						boolean success = false;
						if(message.getObjContents().get(0)!=null && message.getObjContents().get(1)!=null){
							//extract groupname
							String groupname = (String)message.getObjContents().get(0);
							//extract token
							UserToken token = (UserToken)message.getObjContents().get(1);
							//create group will return true or false depending on success of deleting group
							success = deleteGroup(groupname, token);
						}
						if(success) {
							response = new Envelope("OK");
						}
						else{
							response = new Envelope("FAIL");
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
				     /* Added for Phase 2*/
					if(message.getObjContents().size()<2){		//check envelope has enough arguments
						response = new Envelope("FAIL");
					}
					else{
						List<String> memList = null;	//declare the member list
						boolean success = false;
						if(message.getObjContents().get(0)!=null && message.getObjContents().get(1)!=null){
							//extract groupname
							String groupname = (String)message.getObjContents().get(0);
							//extract token
							UserToken token = (UserToken)message.getObjContents().get(1);
							//create group will return true or false depending on success of creating group
							memList = listMembers(groupname, token);
							if(memList != null)success = true;
						}
						if(success) {
							response = new Envelope("OK");
							response.addObject(memList);
						}
						else{
							response = new Envelope("FAIL");
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
				     /* Added for Phase 2*/
					if(message.getObjContents().size()<3){		//envelope needs user, groupname, and requester token
						response = new Envelope("FAIL");
					}
					else{
						response = new Envelope("FAIL");	//set default to be fail
						if(message.getObjContents().get(0)!=null && message.getObjContents().get(1)!=null && message.getObjContents().get(2)!=null){
							//extract String of user to add
							String username = (String)message.getObjContents().get(0);
							//extract String groupname of group to add user to
							String groupname = (String)message.getObjContents().get(1);
							//get requester's token
							UserToken token = (UserToken)message.getObjContents().get(2);
							//add to the group
							boolean success = addUserToGroup(username, groupname, token);
							if(success){
								response = new Envelope("OK");	//if we succeeded, send back an OK
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
				    /* Added for Phase 2*/
					if(message.getObjContents().size()<3){
						response = new Envelope("FAIL");	//envelope not formatted properly
					}
					else{
						response = new Envelope("FAIL"); //set default to be fail
						if(message.getObjContents().get(0)!=null && message.getObjContents().get(1)!=null && message.getObjContents().get(2)!=null){
							//extract String of user to add
							String username = (String)message.getObjContents().get(0);
							//extract String groupname of group to add user to
							String groupname = (String)message.getObjContents().get(1);
							//get requester's token
							UserToken token = (UserToken)message.getObjContents().get(2);
							//add to the group
							boolean success = deleteUserFromGroup(username, groupname, token);
							if(success){
								response = new Envelope("OK");	//if we succeeded, send back an OK
							}
						}
					}
					output.writeObject(response);
				}
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}
				//for testing only!!! -----------------------------------------------------
				/*
				else if(message.getMessage().equals("LISTEVERYTHING")){
					System.out.println("Test point 1");
					if(message.getObjContents().get(0) != null){
						System.out.println("Test point 2");
						UserToken token = (UserToken)message.getObjContents().get(0);
						String requester = token.getSubject();
						if(my_gs.userList.checkUser(requester)){
							System.out.println("Test point 3");
							ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
							//requester needs to be an administrator
							if(temp.contains("ADMIN")) {
								System.out.println("GROUPS:");
								my_gs.groupList.listGroups();
								System.out.println("USERS: ");
								my_gs.userList.listUsers();
							}
						}
					}
				} */
				//------------------------------------------------------------------------------
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					output.writeObject(response);
				}
			}while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

	//Method to create tokens
	private UserToken createToken(String username)
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			//Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		}
		else
		{
			return null;
		}
	}


	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}
					
					
					for(int index =0; index < deleteFromGroups.size(); index++) {
						deleteUserFromGroup(username, deleteFromGroups.get(index), yourToken);
					}
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				}
				else
				{
					return false; //User does not exist

				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	/*---------------------------------------------------------------------------------------------------------------------------------------------------*/
	// Added methods for phase 2
	/*
		This method allows the owner of token to delete the specified group, provided that
	they are the owner of that group. After deleting a group, no user should be a member
	of that group.

	*/
	private boolean deleteGroup(String groupname, UserToken token){
		token.getGroups(); //get groups

		String requester = token.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			if(!my_gs.groupList.checkGroup(groupname)){
					System.out.println("Nonexistent group cannot be deleted");
					return false;		//group needs to exist for it to be deleted
				}
				
			//requester needs to be an owner
		if(my_gs.groupList.getGroupOwner(groupname).equals(requester)){
				//get a copy of the users
				ArrayList<String> temp = my_gs.groupList.listMembers(groupname);
				//delete the group from the users's groups (includes owner)
				for(int index = 0; index < temp.size(); index++)
				{
					my_gs.userList.removeGroup(temp.get(index) , groupname);
				}
				//remove it from the group list
				my_gs.groupList.deleteGroup(groupname);
				return true;
			}
			else{
				System.out.println("Not owner of group.");
				return false;	//requester is not owner of group
			}
		}
		else
		{
			return false; //requester does not exist
		}

	}
	/*
		This method allows the owner of token to create a new group. The owner of token
		should be flagged as the owner of the new group. Any user can create a group.
	*/
	private boolean createGroup(String groupname, UserToken token){

		String requester = token.getSubject();
		
		//if grup exists, cannot create it
		if(my_gs.groupList.checkGroup(groupname)){
				System.out.println("Group already exists");
				return false;
			}
		
		//requester need to exist
		if(my_gs.userList.checkUser(requester)){
				//create group
				my_gs.groupList.addGroup(groupname);		//create the group
				//add requester to group
				my_gs.groupList.addUserToGroup(requester, groupname);
				//make requester owner of new group
				my_gs.groupList.setOwnership(requester, groupname);		//make them owner of ADMIN group
				//add the group the list of groups that the user is in
				my_gs.userList.addGroup(requester, groupname);
				//add group the list of ownerships that the user has
				my_gs.userList.addOwnership(requester, groupname);
				return true;
		}
		else{
			return false;	//requester does not exist
		}
	}
	/*
		This method enables the owner of token to add the user user to the group group.
		This operation requires that the owner of token is also the owner of group
	*/
	private boolean addUserToGroup(String user, String groupname, UserToken token){

		String requester = token.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			//does user exist?
			if(!(my_gs.userList.checkUser(user))){
				System.out.println("User does not exist.");
				return false;
			}
			if(!(my_gs.groupList.checkGroup(groupname))){
					System.out.println("Group does not exist");
					return false;		//group needs to exist to be able to add to it
			}
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an owner
			if(my_gs.groupList.getGroupOwner(groupname).equals(requester)){
				//add user to group
				if(my_gs.groupList.addUserToGroup(user, groupname)){		//check if user is already in group
					//add group to user's list
					my_gs.userList.addGroup(user, groupname);
					return true;
				}
				else {
					System.out.println("User is already in group.");
					return false;
				}

			}
			else{
				System.out.println("Requester does not own group.");
				return false;	//requester is not owner of group
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	/*
		This method enables the owner of token to remove the user user from the group
		group. This operation requires that the owner of token is also the owner of group.

	*/
	private boolean deleteUserFromGroup(String user, String groupname, UserToken token){
		String requester = token.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			if(!my_gs.groupList.checkGroup(groupname)){
					return false;		//group needs to exist to have any users to delete
				}
			//requester needs to be an owner
			if(my_gs.groupList.getGroupOwner(groupname).equals(requester)){
				if(my_gs.groupList.removeUserFromGroup(user, groupname)){		//should return true if removal was successful
					my_gs.userList.removeGroup(user, groupname);				//remove the group from the users
					return true;
				}
				else {
					System.out.println("User was not in group.");
					return false;	//user wasn't in list
				}

			}
			else {
				System.out.println("Requester is not owner of group.");
				return false;	//requester is not owner of group
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	/*
		Provided that the owner of token is also the owner of group, this method will return
		a list of all users that are currently members of group.
	*/
	List<String> listMembers(String groupname, UserToken token){
		String requester = token.getSubject();

		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//group needs to exist
			if(!(my_gs.groupList.checkGroup(groupname))){
				System.out.println("Group does not exist");
				return null;
			}
			//requester needs to be an owner
			if(my_gs.groupList.getGroupOwner(groupname).equals(requester)){
				ArrayList<String> members = my_gs.groupList.listMembers(groupname);
				return members;

			}
			else{
				System.out.println("Requester is not owner of group");
				return null;	//requester is not owner of group
			}
		}
		else
		{
			return null; //requester does not exist
		}
	}


}
