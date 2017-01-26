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
		private Key hmacKey;
		private byte[] userNonce;
		private byte[] groupNonce;
		private int incomingCount;
		private int outgoingCount;
		private boolean serverNonceResponseVerified = false;
		private boolean nonceResponseSent = false;
		boolean counterStarted = false;
		Key fsKey;
		HashMap<String,ArrayList<FileKeyPair>> fileKeys;

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
		@SuppressWarnings("unchecked")
		public UserToken authenticate(String username, String password)
	 {
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;

			//STEP 1 --------------------------------------------------------------
			// byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
			userNonce = crypto.generateNonce(256);
			sharedKey = crypto.generateAesKey(256);
			hmacKey = crypto.generateAesKey(256);
			// System.out.println("HMAC key right after creation: " + Base64.getEncoder().encodeToString(hmacKey.getEncoded()));
			byte[] aesKeyBytes = sharedKey.getEncoded();
			byte[] hmacKeyBytes = hmacKey.getEncoded();
			byte[] iv = crypto.getIV();
			//Testing
			//System.out.println("LENGTHS:    username: " + usernameBytes.length + " || nonce: " + userNonce.length + " || aesKey: " + aesKeyBytes.length + " || iv: " + iv.length);

			//Put all the parts together to form: {username||R1||K_AG || K_AG2 || IV}
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			try{
				outputStream.write( userNonce);
				outputStream.write(aesKeyBytes);
				outputStream.write(hmacKeyBytes);
				outputStream.write(iv);
				// outputStream.write( usernameBytes );
			}
			catch(Exception e){
				System.out.println("Error with ByteArrayOutputStream");
				System.exit(0);
			}
			byte message1[] = outputStream.toByteArray( );
			//Encrypt it
			byte[] m1Encrypted = crypto.rsaEncrypt(message1, gsKey);

			//Tell the server to return a token.
			System.out.println("Sending message 1 to group server.");
			message = new Envelope("AUTHENTICATE1");
			message.addObject(m1Encrypted); //Add encrypted message
			output.writeObject(message);		//send it!

			//Get the response from the server
			Envelope wrapper = (Envelope)input.readObject();
			System.out.println("Received message 2 from server" + wrapper.getMessage());
			response = extractResponse(wrapper, output, input);
			//Successful response
			if(response.getMessage().equals("OK")) {
				//Step 2 --------------------------------------------------------------------------------
				byte[] groupNonceResponse = generateNonceResponse(groupNonce);
				//T7: getting hash of public key of File Server
				if ((fsKey = ClientGUI.fsKey) == null)
					fsKey = ClientApp.fsKey;

				byte[] fsKeyHash = crypto.hashSHA_256(fsKey.getEncoded());
				//make the envelope
				Envelope inner = new Envelope("AUTHENTICATE2");
				inner.addObject(groupNonceResponse);
				inner.addObject(username);
				inner.addObject(password);
				inner.addObject(fsKeyHash);

				wrapper = packageRequest(inner);
				System.out.println("Sending message 3 to server.");
				output.writeObject(wrapper);		//send it!
				incomingCount = 0;
				outgoingCount = 0;
				counterStarted = true;

				//Get the response from the server
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				if(response.getMessage().equals("OK")){
					System.out.println("Receiving message 4 from server");
					ArrayList<Object> temp = response.getObjContents();
					token = (UserToken)temp.get(1);
					//T6: Build the HashMap for the keys to be stored in
					fileKeys = new HashMap<String,ArrayList<FileKeyPair>>();
					System.out.println("Size of received Envelope: " + temp.size());
					for(int i=2; i<temp.size();i++){
						ArrayList<FileKeyPair> tempKeys = (ArrayList<FileKeyPair>)temp.get(i);
						String current = tempKeys.get(0).getGroupName();
						System.out.println("Received keys for group: " + current + "|| Size of key list: " + tempKeys.size());
						fileKeys.put(current, tempKeys);
					}
					return token;
				}
				else{
					System.out.println("Incorrect password.");
					incomingCount = 0;
					outgoingCount = 0;
					counterStarted = false;
					serverNonceResponseVerified = false;
					return null;
				}
			}
			else if (response.getMessage().equals("FAIL-USERLOCKED")){
				System.out.println("User is on timeout! Try again in 15 minutes.");
				incomingCount = 0;
				outgoingCount = 0;
				counterStarted = false;
				serverNonceResponseVerified = false;
				return null;
			}
			else{
				System.out.println("User does not exist.");
				incomingCount = 0;
				outgoingCount = 0;
				counterStarted = false;
				serverNonceResponseVerified = false;
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
			//generate hash of fsKey
			byte[] fsKeyHash = crypto.hashSHA_256(fsKey.getEncoded());

			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username);
			message.addObject(fsKeyHash);
			Envelope wrapper = packageRequest(message);

			output.writeObject(wrapper);
			System.out.println("Sending message requesting for new token.");

			//Get the response from the server
			wrapper = (Envelope)input.readObject();
			response = extractResponse(wrapper, output, input);
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				token = (Token)response.getObjContents().get(1);
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

				message = new Envelope("CUSER");
				message.addObject(username);
				message.addObject(password);
				message.addObject(token);

				Envelope wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to server to create user.");

				//get response
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);

				System.out.println("Received a response from server.");
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}

				System.out.println("Failure to create user " + response.getMessage());
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
				Envelope message = null, wrapper = null, response = null;
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name string
				message.addObject(token);

				wrapper = packageRequest(message);

				output.writeObject(wrapper);
				System.out.println("Sent request to server to delete user.");

				//get response
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				// System.out.println("Received a response from server.");

				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					System.out.println("size of message recieved"  + response.getObjContents().size());
					for (int i = 1; i < response.getObjContents().size(); i++){
						FileKeyPair kp = (FileKeyPair)(response.getObjContents().get(i));
						String groupname = kp.getGroupName();
						System.out.println("Got back new FileKeyPair for group with name " + groupname);
						ArrayList<FileKeyPair> tempList = fileKeys.get(groupname);
						tempList.add(kp);
						fileKeys.put(groupname, tempList);
					}
					return true;
				}
				System.out.println("Failure to delete user " + response.getMessage());
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
				Envelope message = null, wrapper = null, response = null;

				message = new Envelope("CGROUP");
				message.addObject(groupname);
				message.addObject(token);

				wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to server to create a group.");

				//get response
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				System.out.println("Received a response from server.");

				if(response.getMessage().equals("OK"))
				{
					//T6: Get the key pair given bac kand put it into your own hashmap
					FileKeyPair kp = (FileKeyPair)(response.getObjContents().get(1));
					System.out.println("Created group! Got back FileKeyPair for group with name " + kp.getGroupName());
					ArrayList<FileKeyPair> tempList = new ArrayList<FileKeyPair>();
					tempList.add(kp);
					fileKeys.put(groupname, tempList);
					return true;
				}
				System.out.println("Error creating group: " + response.getMessage());
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
				Envelope message = null, wrapper = null, response = null;

				//Tell the server to delete a user
				message = new Envelope("DGROUP");
				message.addObject(groupname);
				message.addObject(token);

				wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to server to delete a group.");

				//get response
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				System.out.println("Received a response from server.");

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
				Envelope message = null, wrapper = null, response = null;

				//Tell the server to create a user
				message = new Envelope("LMEMBERS");
				message.addObject(groupname);
				message.addObject(token);

				wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to list members of a group.");


				//get response
				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				System.out.println("Received a response from server.");

				if(response.getMessage().equals("OK"))
				{
					List<String> list = (List)response.getObjContents().get(1);
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
		}
	 //-------------------------------------------------------------------------------------------------------

	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, wrapper = null, response = null;

				//Tell the server to create a user
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username);
				message.addObject(groupname);
				message.addObject(token);

				wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to server to add user to group.");

				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				System.out.println("Received a response from server.");
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
				Envelope message = null, wrapper = null, response = null;

				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username);
				message.addObject(groupname);
				message.addObject(token);

				wrapper = packageRequest(message);
				output.writeObject(wrapper);
				System.out.println("Sent request to server to delete user from group.");

				//get response

				wrapper = (Envelope)input.readObject();
				response = extractResponse(wrapper, output, input);
				if(response.getMessage().equals("OK"))
				{
					//T6: Get the key pair given bac kand put it into your own hashmap
					FileKeyPair kp = (FileKeyPair)(response.getObjContents().get(1));
					System.out.println("Created group! Got back FileKeyPair for group with name " + kp.getGroupName());
					ArrayList<FileKeyPair> tempList = fileKeys.get(groupname);
					tempList.add(kp);
					fileKeys.put(groupname, tempList);
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
		System.out.print("Testing to see if group server's challenge response is accurate.");
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

	private Envelope packageRequest(Envelope inner) {
		if (counterStarted) {
			inner.getObjContents().add(0, outgoingCount);
			outgoingCount++;
			// System.out.println("Added counter to message " + outgoingCount);
		}
		byte[] envelopeBytes = Utils.serialize(inner);
		byte[] ciphertextBytes = crypto.aesEncrypt(envelopeBytes, sharedKey);

		byte[] hmac = crypto.hmac(ciphertextBytes, hmacKey);

		Envelope wrapper = new Envelope("AES");
		wrapper.addObject(ciphertextBytes);
		wrapper.addObject(hmac);
		return wrapper;
	}

	private Envelope extractResponse(Envelope wrapper, ObjectOutputStream output, ObjectInputStream input) {
		// System.out.println(wrapper.getMessage());
		byte[] ciphertextBytes = (byte[])wrapper.getObjContents().get(0);
		byte[] hmac = (byte[])wrapper.getObjContents().get(1);

		//verify hmac
		boolean validHmac = crypto.verifyHmac(hmac, ciphertextBytes, hmacKey);
		if (!validHmac) {
			System.out.println("Invalid HMAC from server! Envelope contents may have been tampered with.");
			System.out.println("Will disconnect now.");
			try{
				input.close();
				output.close();
				this.disconnect();
			}
			catch (Exception e){};
			return null;
		}
		System.out.println("\nIntegrity of response verified with HMAC.\n");
		// HMAC valid so continue and decrypt inner envelope

		byte[] envelopeBytes = crypto.aesDecrypt(ciphertextBytes, sharedKey);
		Envelope inner = (Envelope)Utils.deserialize(envelopeBytes);

		String message = inner.getMessage();
		System.out.println("Inner message " + message);
		if (message.length() >= 4 && message.substring(0,4).equals("FAIL")){
			System.out.println(message);
			// only continue if authentication2 complete, otherwise return now
			if (message.equals("FAIL-USERLOCKED") || message.equals("FAIL-USER/PASSWORD"))
				return inner;
		}

		// check server nonce if we haven't done so yet
		if (!serverNonceResponseVerified) {
			byte[] serverNonceResponse = (byte[])inner.getObjContents().get(0);
			boolean valid = verifyNonceResponse(serverNonceResponse);
			if (!valid){
				System.out.println("Invalid nonce response from server!");
				System.out.println("Will close connection now");
				try{
					input.close();
					output.close();
					this.disconnect();
					return null;
				}
				catch (Exception e){};
			}

			groupNonce = (byte[])inner.getObjContents().get(1);
			serverNonceResponseVerified = true;
			System.out.println("Group server nonce response valid.");
		}

		if (counterStarted) {
			Integer count = (Integer)inner.getObjContents().get(0);
			System.out.println("Count of message received: " + count);
			if (count != incomingCount) {
				System.out.println("Message out of order! Connection will be terminated. Should be " + incomingCount);
				try{
					input.close();
					output.close();
					this.disconnect();
					return null;
				}
				catch (Exception e){};
			}
			//
			System.out.println("Message order verified.");
			incomingCount++;
		}
		return inner;
	}


	//Phase 5: Allow user to change password
	public boolean changePassword(String oldpass, String newpass, UserToken token)
	{
		 try
		 {
			 Envelope message = null, wrapper = null, response = null;
			 //Tell the server to change password
			 message = new Envelope("CHANGEPASS");
			 message.addObject(oldpass);
			 message.addObject(newpass);
			 message.addObject(token);
			 wrapper = packageRequest(message);
			 output.writeObject(wrapper);
			 System.out.println("Sent request to server to change password.");

			 //get response
			 wrapper = (Envelope)input.readObject();
			 response = extractResponse(wrapper, output, input);
			 System.out.println("Received a response from server.");

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

}
