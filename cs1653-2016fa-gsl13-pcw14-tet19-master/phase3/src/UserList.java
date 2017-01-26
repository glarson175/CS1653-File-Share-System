/* This list represents the users on the server */
import java.util.*;


	public class UserList implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		private Hashtable<String, User> list = new Hashtable<String, User>();

		//FOR TESTING ONLY
		/*
		public synchronized void listUsers(){
			System.out.println(list.toString());
		}
		*/

		public UserList(){

		}

		public UserList(Hashtable<String, User> list){
			this.list = list;
		}

		public synchronized void addUser(String username)
		{
			User newUser = new User();
			list.put(username, newUser);
		}

		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}

		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		public synchronized ArrayList<String> getUserGroups(String username)
		{
			return list.get(username).getGroups();
		}

		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}

		public synchronized void addGroup(String user, String groupname)
		{
			list.get(user).addGroup(groupname);
		}

		public synchronized void removeGroup(String user, String groupname)
		{
			list.get(user).removeGroup(groupname);
		}

		public synchronized void addOwnership(String user, String groupname)
		{
			list.get(user).addOwnership(groupname);
		}

		public synchronized void removeOwnership(String user, String groupname)
		{
			list.get(user).removeOwnership(groupname);
		}

		public UserList deepCopyUserList(){
			Hashtable<String, User> copyTable = new Hashtable<String, User>();
			for (String s : list.keySet()){
				User u = list.get(s);
				User uCopy = u.deepCopyUser();
				copyTable.put(s,uCopy);
			}
			UserList listCopy = new UserList(copyTable);
			return listCopy;
		}

		public String toString(){
			StringBuilder s = new StringBuilder();
			for (String name : list.keySet()){
				s.append ("User name: " + name + "; User Info: ");
				User u = list.get(name);
				s.append(u);
			}
			return s.toString();
		}


	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;

		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public User(ArrayList<String> groups, ArrayList<String> ownership)
		{
			this.groups = groups;
			this.ownership = ownership;
		}

		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
				else{
					System.out.println("This user is not in group " + group);
				}
			}
			else{
				System.out.println("This user is not in any groups.");
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

		public User deepCopyUser() {
			ArrayList<String> copyGroups= new ArrayList<String>();
			ArrayList<String> copyOwnership = new ArrayList<String>();
			for (String g : this.groups)
				copyGroups.add(g);
			for (String o : this.ownership)
				copyOwnership.add(o);
			User copy = new User(copyGroups, copyOwnership);
			return copy;
		}

		public String toString(){
			StringBuilder s = new StringBuilder();
			s.append("Member of: ");
			for (String g : groups)
				s.append (g + ", ");
			s.append("Owns groups ");
			for (String o : ownership)
				s.append(o + ", ");
			return s.toString();
		}

	}

}
