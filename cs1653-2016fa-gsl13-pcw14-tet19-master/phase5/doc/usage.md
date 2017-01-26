# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - ON WINDOWS:
    * Type `java -cp ".;bc.jar" RunGroupServer [port number]`
 - ON LINUX/MAC:
    * Type `java -cp "bc.jar" RunGroupServer [port number]``

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username and password. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

Furthermore, when the group server is first started, it will also generate its own RSA key pair.

Note: Any subsequent runs, even with a different port number, will still use that same RSA key pair.

## Running the File Server
PRIOR TO STARTING ANY FILE SERVER:
 - run `java -cp ".;bc.jar" GetGroupServerKey` (Windows) OR `java -cp "bc.jar" GetGroupServerKey` (MAC/LINUX)
    * This program will ask for the Group Server's address and port to connect to.
    * This program will prompt whoever is about to run the file server whether or not they trust the group server's key.
    * It is up to the administrator of the File Server to verify this offline (phone, in person, etc.)
    * Upon verifying the key, the program will close and save a .config file for the File Server.

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - ON WINDOWS:
    * Type `java -cp ".;bc.jar" RunFileServer [port number]`
 - ON LINUX/MAC:
    * Type `java -cp "bc.jar" RunFileServer [port number]``


Note that the port number argument to `RunFileServer` is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will NOT run correctly
The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Shutting Down the Servers

To shut down the group server, enter the directory containing ShutdownGS.class and input the address and port when prompted.

To shut down the file server, enter the directory containing ShutdownFS.class and input the address and port when prompted.


## Resetting the Group or File Server

To reset the Group Server, delete the file `UserList.bin` or `GroupList.bin` or `Database.bin` or `KeyDatabase.bin`. Deleteing any of these, will prompt Group Server to recreate all three.

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.

## Running GUI Client

Run Group Server and File Server in other terminals (other computers, same computers, etc.)
 - Enter directory containing `RunClientGUI.class`
 - ON WINDOWS
  * Type `java -cp ".;bc.jar" RunClientGUI`
 - ON MAC/LINUX
  * Type `java -cp "bc.jar" RunClientGUI`
 - Then, you will be prompted if you trust the group server and file server publics keys. (It is entirely up to the user to verify these offline) Note: Any previous trusted keys will be saved as trusted and will not be prompted for trustworthiness for future use.
 - Next, the user will be prompted for username and password.
 - Finally, upon a correct username/password submission, the user will arrive at a menu to perform actions described below that are described below in the section titled "Menu Commands".

## Running Console Client

Run Group Server and File Server in other terminals (other computers, same computers, etc.)
- Enter directory containing `ClientApp.class`
- ON WINDOWS
 * Type `java -cp ".;bc.jar" RunClientGUI`
- ON MAC/LINUX
 * Type `java -cp "bc.jar" RunClientGUI`


You will be prompted for the address of fileserver and groupserver. Leaving these blank (i.e. hitting enter without typing anything) will default these to `localhost`.<br />

- Then, you will be prompted if you trust the group server and file server publics keys. (It is entirely up to the user to verify these offline) Note: Any previous trusted keys will be saved as trusted and will not be prompted for trustworthiness for future use.
- Next, the user will be prompted for username and password.
 - Finally, upon a correct username/password submission, the user will arrive at a menu to perform actions described below that are described below in the section titled "Menu Commands".

## Men Commands
	1. Upload File<br />
	2. Download File<br />
	3. Delete File<br />
	4. List Files<br />
	5. Create group<br />
	6. Delete group<br />
	7. Add user to group<br />
	8. Delete user from group<br />
	9. List members of group<br />
	10. Create user (Admin-only)<br />
	11. Delete user (Admin-only)<br />

#Upload File
Type `1` as your action. First, enter the name of the file on your computer to upload. Second, give the name on the server. Third, type the name of the group to share the file with.

#Download File
Type `2` as your action. First, enter the name of the file you want to download. Second, give the 'destination' name of the file.

#Delete file
Type `3` as your action. Enter the name of the file you want to delete.

#List Files
Type `4` as your action. This should list all files you have access to.

#Create Group
Type `5` as your action. Enter the name of the group you wish to create.

#Delete Group
Type `6` as your action. Enter the name of the group you wish to delete.

#Add User to Group
Type `7` as your action. First, enter the name of the user you wish to add. Second, enter the name of the group you wish to add the user to.

#Remove User from Group
Type `8` as your action. First, enter the name of the user you wish to remove. Second, enter the name of the group you wish to remove the user form.

#List members of a group
Type `9` as your action. Type the name of the group you wish to list the members of.

#Create User
Type `10` as your action. Type the name of the user you wish to create.

#Delete User
Type `11` as your action. Type the name of the user you wish to delete.
