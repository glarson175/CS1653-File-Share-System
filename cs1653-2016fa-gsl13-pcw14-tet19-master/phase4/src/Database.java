/* Database that stores users' h(salt||password) and salt */
import java.util.*;
import java.nio.charset.*;
import java.io.*;
import java.security.*;

public class Database implements java.io.Serializable {
		private static final long serialVersionUID = 4443127729074236688L;

		private PrivateKey privateKey;
		private PublicKey publicKey;
		private Hashtable<String, Item> list = new Hashtable<String, Item>();
		private static Crypto crypto = new Crypto();


		//constructors
		public Database(){
			crypto = new Crypto();
			System.out.println("Database: Generating key pair!");
			KeyPair kp = crypto.generateRSAKeyPair(2048); //2048 RSA key pair
			privateKey = kp.getPrivate();
			publicKey = kp.getPublic();
			//System.out.println("Database - Public key: " + Arrays.toString(publicKey.getEncoded()));
		}

		public Database(Hashtable<String, Item> list){
			this.list = list;
			crypto = new Crypto();
			KeyPair kp = crypto.generateRSAKeyPair(2048); //2048 RSA key pair
			Key privateKey = kp.getPrivate();
			Key publicKey = kp.getPublic();
		}

		public PublicKey getPublicKey(){
			return publicKey;
		}
		public PrivateKey getPrivateKey(){
			return privateKey;
		}

		//add new user to the database
		public synchronized boolean addItem(String username, String pass)
		{
			try{
				//generate salt and pass bytes
				byte[] passBytes = pass.getBytes(StandardCharsets.UTF_8);
				byte[] salt = crypto.generateSalt(256);					//256 bit salt
				//concatenate together for hashing
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
				outputStream.write( salt );
				outputStream.write( passBytes );
				byte[] item = outputStream.toByteArray( );
				//Hash it
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] hashedPass = digest.digest(item);
				//add it to the database
				Item newItem = new Item(hashedPass, salt);
				list.put(username, newItem);
				return true;
			}
			catch(Exception e){
				System.out.println("Database Error: " + e.toString());
				return false;
			}

		}
		//delete user from database
		public synchronized boolean deleteItem(String username)
		{
			if(list.remove(username) != null){
				return true;
			}
			else{
				return false;
			}
		}

		//checks to see if a user is in the database
		public synchronized boolean checkItemExists(String username)
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

		//check to validate that a username/password pair is valid
		public synchronized boolean checkItem(String username, String pass){
			try{
				//generate salt and pass bytes
				byte[] passBytes = pass.getBytes(StandardCharsets.UTF_8);
				byte[] salt = getSalt(username);
				//concatenate together for hashing
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
				outputStream.write( salt );
				outputStream.write( passBytes );
				byte[] item = outputStream.toByteArray( );
				//Hash it
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] hashedPass = digest.digest(item);
				//get the hashed pass in storaged for comparison
				byte[] storedHashedPass = getHashedPass(username);
				return Arrays.equals(hashedPass, storedHashedPass);
			}
			catch(Exception e){
				System.out.println("Database Error: " + e.toString());
				return false;
			}
		}

		//mutator
		public synchronized void updateItem(String username, byte[] newHashedPass, byte[] newSalt){
			list.get(username).update(newHashedPass, newSalt);
		}

		//internal accessor methods, not shown to avoid leaky abstraction
		private synchronized byte[] getSalt(String username){
			return list.get(username).getSalt();
		}
		private synchronized byte[] getHashedPass(String username){
			return list.get(username).getHashedPass();
		}

		class Item  implements java.io.Serializable {
				private static final long serialVersionUID = -7649255709511719574L;

				private byte[] hashedPass;
				private byte[] salt;

				public Item(byte[] hashedPass, byte[] salt){
					this.hashedPass = hashedPass;
					this.salt = salt;
				}

				public byte[] getHashedPass(){
					return hashedPass;
				}
				public byte[] getSalt(){
					return salt;
				}
				public void update(byte[] newHash, byte[] newSalt){
					hashedPass = newHash;
					salt = newSalt;
				}
}
}
