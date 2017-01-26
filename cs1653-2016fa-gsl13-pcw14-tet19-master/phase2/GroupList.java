/* This list represents the GROUPS on the server */
/*General notes: Most of this is VERY similar to UserList just altered to fit with groups instead  
				HOWEVER, many of the methods return booleans rather than just void statements
				If these methods do not succeed, then they should be used as a check as to whether or
				not to run the corresponding method in UserList */

import java.util.*;

	public class GroupList implements java.io.Serializable {
	
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, Group> list = new Hashtable<String, Group>();
		
		//FOR TESTING ONLY
		/*
		public synchronized void listGroups(){
			System.out.println(list.toString());
		}*/
		
		//add group to list
		public synchronized boolean addGroup(String group_name)
		{
			Group new_group = new Group();
			if(checkGroup(group_name)){
				System.out.println("Group already exists.");
				return false;
			}
			list.put(group_name, new_group);
			return true;
		}
		
		//remove group from list
		public synchronized boolean deleteGroup(String group_name)
		{
			if(!list.containsKey(group_name)){
				System.out.println("Nonexistent cannot be deleted");
				return false;
			}
			list.remove(group_name);
			return true;
		}
		//check if group is in list
		public synchronized boolean checkGroup(String group_name)
		{
			if(list.containsKey(group_name))
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		
		//list members
		public synchronized ArrayList<String> listMembers(String group_name)
		{
			return list.get(group_name).getMembers();
		}
		
		//get group owner
		public synchronized String getGroupOwner(String group_name)
		{
			return list.get(group_name).getOwnership();
		}
		
		//add user to a group
		public synchronized boolean addUserToGroup(String user, String group_name)
		{
			return list.get(group_name).addUser(user);
		}
		
		//remove user from group
		public synchronized boolean removeUserFromGroup(String user, String group_name)
		{
			return list.get(group_name).removeUser(user);
		}
		//set ownership
		public synchronized boolean setOwnership(String user, String group_name)
		{
			return list.get(group_name).setOwnership(user);
		}
		
		
		
		//NOTE: Do we really want multiple owners??????
	
	class Group implements java.io.Serializable {

		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> members;
		private String ownership;		//allowing only one owner
		
		//default constructorz
		public Group()
		{
			members = new ArrayList<String>();
			ownership = null;
		}
		
		//return a list of the members
		public ArrayList<String> getMembers()
		{
			return members;
		}
		//return the name of the owner
		public String getOwnership()
		{
			return ownership;
		}
		//add a user to the group
		public boolean addUser(String username)
		{
			//check to see if user is already in group
			if(members.contains(username)) {
					System.out.println("User is already in group.");
					return false;
			}
			members.add(username);
			return true;
		}
		//remove user from the group
		public boolean removeUser(String username)
		{
			if(!members.isEmpty())
			{
				if(members.contains(username))
				{
					return members.remove(username);
				}
			}
			return false;
		}
		//set an owner
		public boolean setOwnership(String username)
		{
			if(!members.isEmpty() && members.contains(username)){
				ownership = username;
				return true;
			}
			else{
				System.out.println("New owner must be a member in group first.");
				return false;
			}
				
		}
		
	}
	
}	
