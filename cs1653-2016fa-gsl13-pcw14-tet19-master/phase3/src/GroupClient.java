/* Implements the GroupClient Interface */

import java.util.*;
import java.io.*;
import java.security.*;
import java.nio.charset.*;
import java.math.*;
import javax.crypto.spec.*;

public class GroupClient extends Client implements GroupClientInterface {
		private final static byte[] nullspace = new byte[]{(byte)0x00};
		private static Crypto crypto = new Crypto();
		private PublicKey gsKey;
		private Key sharedKey;
		private byte[] userNonce;
		private byte[] groupNonce;

		public PublicKey getGSKey(){
			try{
				PublicKey key = null;
				Envelope message = null, response = null;
				//tell the server to return a token
				message= new Envelope("GETKEY");
				message.addObject(null);
				output.writeObject(message);
				//get response from server
				response = (Envelope)input.readObject();
				//success!
				if(response.getMessage().equals("OK")){
					//If there is a token in the Envelope, return it
					ArrayList<Object> temp = null;
					temp = response.getObjContents();

					if(temp.size() == 1)
					{
						key = (PublicKey)temp.get(0);
						//System.out.println("From group client: Succesfully received group server's key!");
						gsKey = key;
						return key;
					}
					else{
						System.out.println("From group client: Something went wrong.");
					}
				}
			}
			catch(Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
			return null;
		}


		//Method for INITIAL AUTHENTICATION OF USER
		public UserToken authenticate(String username, String password)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//STEP 1 --------------------------------------------------------------
			byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
			userNonce = crypto.generateNonce(256);
			sharedKey = crypto.generateAesKey(128);		//TO-DO: 256 bit aesKey
			byte[] aesKeyBytes = sharedKey.getEncoded();
			byte[] iv = crypto.getIV();
			//Testing
			//System.out.println("LENGTHS:    username: " + usernameBytes.length + " || nonce: " + userNonce.length + " || aesKey: " + aesKeyBytes.length + " || iv: " + iv.length);

			//Put all the parts together to form: {username||R1||K_AG}
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			try{
				outputStream.write( usernameBytes );
				outputStream.write( userNonce);
				outputStream.write(aesKeyBytes);
				outputStream.write(iv);
			}
			catch(Exception e){
				System.out.println("Error with ByteArrayOutputStream");
				System.exit(0);
			}
			byte message1[] = outputStream.toByteArray( );
			//Encrypt it
			byte[] m1Encrypted = crypto.rsaEncrypt(message1, gsKey);

			//Tell the server to return a token.
			System.out.println("Sending message 1 to server.");
			message = new Envelope("AUTHENTICATE1");
			message.addObject(m1Encrypted); //Add encrypted message
			output.writeObject(message);		//send it!

			//Get the response from the server
			response = (Envelope)input.readObject();
			System.out.println("Received message 2 from server");
			//Successful response
			if(response.getMessage().equals("OK")) {
				//Step 2 --------------------------------------------------------------------------------
				byte[] m2Encrypted = (byte[])response.getObjContents().get(0);
				//Decrypt it
				byte[] m2Decrypted = crypto.aesDecrypt(m2Encrypted, sharedKey);
				//Extract all the parts
				byte[] userNonceResponseDecrypted = Arrays.copyOfRange(m2Decrypted, 0, 32);
				groupNonce = Arrays.copyOfRange(m2Decrypted, 32, 64);
				//test to see if the group server's challenge response is accurate
				if(verifyNonceResponse(userNonceResponseDecrypted)){
					//STEP 3 ----------------------------------------------
					//generate response to challenge and password
					byte[] groupNonceResponse = generateNonceResponse(groupNonce);
					byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
					//put all the parts together to form: {R2-1 || password}
					outputStream.reset();
					try{
						outputStream.write(groupNonceResponse);
						outputStream.write(passwordBytes);
					} catch( Exception e) {
						System.out.println("Error with bytearrayoutputstream.");
						System.exit(0);
					}
					byte[] message3 = outputStream.toByteArray();
					//Encrypt it
					byte[] m3Encrypted = crypto.aesEncrypt(message3, sharedKey);

					//send it!
					//Tell the server to return a token.
					System.out.println("Sending message 3 to server.");
					message = new Envelope("AUTHENTICATE2");
					message.addObject(m3Encrypted); //Add encrypted message
					output.writeObject(message);		//send it!

					//Get the response from the server
					response = (Envelope)input.readObject();
					if(response.getMessage().equals("OK")){
						System.out.println("Receiving message 4 from server");
						byte[] m4Encrypted = (byte[])response.getObjContents().get(0);
						byte[] m4Decrypted = crypto.aesDecrypt(m4Encrypted, sharedKey);
						groupNonce = Arrays.copyOfRange(m4Decrypted, m4Decrypted.length-32,m4Decrypted.length);
						byte[] tokenBytes = Arrays.copyOfRange(m4Decrypted, 0, m4Decrypted.length-32);
						token = (UserToken)crypto.deserializeToken(tokenBytes);
						return token;
					}
					else{
						System.out.println("Incorrect password.");
						return null;
					}
				}
				else{
					System.out.println("Group client responded to nonce incorrectly!");
					return null;
				}
			}
			else{
				System.out.println("User does not exist.");
				return null;
			}

		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			System.out.println("Something went wrong during authentication. Disconnect and try again.");
			return null;
		}
	 }
		//--------------------------------------------------------------------
		//Method for getting NEW token!
	 public UserToken getToken(String username)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//generate components
			//make nonce
			userNonce = crypto.generateNonce(256);
			//send nonce response
			byte[] groupNonceResponse = generateNonceResponse(groupNonce);
			//put it all together
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			try{
				outputStream.write(userNonce);
				outputStream.write(groupNonceResponse);
			}
			catch(IOException e){
				System.out.println("Something went wront with byte array output stream.");
				return null;
			}
			byte[] m = outputStream.toByteArray();
			//encrypt it
			byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
			//send it
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(mEncrypted); //Add user name string
			output.writeObject(message);
			System.out.println("Sending message requesting for new token.");

			//Get the response from the server
			response = (Envelope)input.readObject();
			//get the message
			byte[] rEncrypted = (byte[])response.getObjContents().get(0);
			//decrypt it
			byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
			//Extract components
			byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 32, 64);
			if(!verifyNonceResponse(userNonceResponse)){
				System.out.println("Group Server's response to challenge is not correct. Disconnect!");
				return null;
			}
			groupNonce = Arrays.copyOfRange(rDecrypted, 0, 32);
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//NOTE: Received message should be in order: groupNonce, userNonceResponse, token
				byte[] tokenBytes = Arrays.copyOfRange(rDecrypted, 64, rDecrypted.length);
				//If there is a token in the Envelope, return it
				token = (UserToken)crypto.deserializeToken(tokenBytes);
				System.out.println("Succesfully got a new token using GET.");
				return token;

			}
			System.out.println("Something went wrong getting a new token :(");
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	 }

	 public boolean createUser(String username, String password, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
				//password bytes
				byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(usernameBytes);
					outputStream.write(nullspace);
					outputStream.write(passwordBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to create user.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(usernameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to delete user.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] groupnameBytes = groupname.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(groupnameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to delete a user
				message = new Envelope("CGROUP");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to create a group.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteGroup(String groupname, UserToken token)
	 {
			try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] groupnameBytes = groupname.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(groupnameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to delete a user
				message = new Envelope("DGROUP");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to delete a group.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 //--------------------------------------------------------------------------------------------------------
	 @SuppressWarnings("unchecked")
		public List<String> listMembers(String groupname, UserToken token)
		 {
				try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] groupnameBytes = groupname.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(groupnameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to create a user
				message = new Envelope("LMEMBERS");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to list members of a group.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return null;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					byte[] listBytes = Arrays.copyOfRange(rDecrypted, 64, rDecrypted.length);
					ByteArrayInputStream byteInput = new ByteArrayInputStream(listBytes);
					ObjectInputStream objectInput = new ObjectInputStream(byteInput);
					List<String> list = (List)objectInput.readObject();
					return list;
				}
				System.out.println("Group does not exist or user is not owner of group!");
				return null;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
			//		return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.

		 }
	 //-------------------------------------------------------------------------------------------------------

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
				//password bytes
				byte[] groupnameBytes = groupname.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(usernameBytes);
					outputStream.write(nullspace);
					outputStream.write(groupnameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to create a user
				message = new Envelope("AUSERTOGROUP");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to add user to group.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//generate components
				//response to group server's challenge
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//generate client's own challenge
				userNonce = crypto.generateNonce(256);
				//username bytes
				byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
				//password bytes
				byte[] groupnameBytes = groupname.getBytes(StandardCharsets.UTF_8);
				//token bytes
				byte[] tokenBytes = crypto.serializeToken((Token)token);
				//put it all together
				ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
					outputStream.write(groupNonceResponse);
					outputStream.write(userNonce);
					outputStream.write(usernameBytes);
					outputStream.write(nullspace);
					outputStream.write(groupnameBytes);
					outputStream.write(nullspace);
					outputStream.write(tokenBytes);
				byte[] m = outputStream.toByteArray();
				//encrypt it
				byte[] mEncrypted = crypto.aesEncrypt(m, sharedKey);
				//Tell the server to create a user
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(mEncrypted); //Add user name string
				output.writeObject(message);
				System.out.println("Sent request to server to delete user from group.");

				//get response
				response = (Envelope)input.readObject();
				System.out.println("Received a response from server.");
				//extract and decrypt response
				byte[] rEncrypted = (byte[])response.getObjContents().get(0);
				byte[] rDecrypted = crypto.aesDecrypt(rEncrypted, sharedKey);
				//extract components
				byte[] userNonceResponse = Arrays.copyOfRange(rDecrypted, 0, 32);
				if(!verifyNonceResponse(userNonceResponse)){
					System.out.println("Group Server's response to challenge is not correct. Disconnect!");
					return false;
				}
				groupNonce = Arrays.copyOfRange(rDecrypted, 32, 64);
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }

	 //HELPER METHODS -------------------------------------------------------------
	public void shutdown()
	{
			try 
			{
				Envelope message = null;
				System.out.println("Sending Shutdown message to Group Server.");
				message = new Envelope("DISCONNECT and SHUTDOWN");
				message.addObject(null); //Add null message
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
	}
	 
	 
	 private boolean verifyNonceResponse(byte[] response){
		System.out.print("Testing to see if user's challenge response is accurate.");
		BigInteger userNonceBigInt = new BigInteger(userNonce);
		userNonceBigInt = userNonceBigInt.subtract(BigInteger.valueOf(1));
		BigInteger userNonceResponse = new BigInteger(response);
		if(userNonceBigInt.equals(userNonceResponse)){
			System.out.println(" Success!");
			return true;
		}
		else{
			System.out.println(" Failure!");
			return false;
		}
	}

	private byte[] generateNonceResponse(byte[] original){
			System.out.println("Computing response to challenge");
			BigInteger responseBigInt = new BigInteger(original);		//computing R1-1
			responseBigInt = responseBigInt.subtract( BigInteger.valueOf(1) );
			byte[] nonceResponse = responseBigInt.toByteArray();
			return nonceResponse;
	}

	public boolean exportPublicKey() {
		if (gsKey == null) return false;
		String keyFile = "GSPublicKey.config";
		FileOutputStream fos = null;
		ObjectOutputStream os = null;
		boolean success = false;
		try
		{
			//read UserList.bin for its contents for userList
			fos = new FileOutputStream(keyFile);
			os = new ObjectOutputStream(fos);
			os.writeObject(gsKey);
			success = true;
		}
		catch (IOException e) {
			System.out.println("Problem writing to key file");
		}
		finally {
			if (fos != null){
				try {fos.close();}
				catch (IOException e){}
			}
			if (os != null) {
				try {os.close();}
				catch (IOException e){};
			}
		}
		return success;
	}

}
