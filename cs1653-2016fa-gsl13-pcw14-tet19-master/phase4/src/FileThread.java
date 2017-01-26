/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.math.*;

public class FileThread extends Thread {

	private final Socket socket;
	private       FileServer my_fs;
	private Crypto crypto;
	private Key publicFSKey;
	private Key privateFSKey;
	private PublicKey gsKey;
	private byte[] fileNonce;
	private byte[] fileNonceResponse;
	private byte[] userNonce;
	private Key sharedKey;
	private Key hmacKey;
	private boolean authenticate1 = false;
	private boolean authenticate2 = false;
	private boolean user_authenticated = false;
	private String[] requestParams;
	private UserToken token;
	private int incomingCount;
	private int outgoingCount;

	public FileThread(Socket _socket, FileServer _fs) {
      socket = _socket;
      my_fs  = _fs;
			crypto = new Crypto();
			publicFSKey = my_fs.getFSpublicKey();
			privateFSKey = my_fs.getFSprivateKey();
			gsKey = my_fs.getGSKey();
		}


	public void run()	{
		boolean proceed = true;
		try { // Establish a connection, create input and output streams

			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			do {
				System.out.println();
				Envelope message = (Envelope) input.readObject();

				/* If envelope message is AES, we have an encrypted envelope
				 	inside another envelope, which needs decrypted first. */
				if (message.getMessage().equals("AES")) {
					user_authenticated = false;
					/* This checks the nonce if it exists, checks the token signature,
					 checks the message count, and sets the requestParams variable */
					message = extractRequest(message, output, input, true);
				}

				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				//Client wants FileServer's public key
				if(message.getMessage().equals("GETKEY")){
					response = new Envelope("OK");
					response.addObject(publicFSKey);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("AUTHENTICATE1")){
					try {

						//decrypt message - must do this before verifying integrity
						byte[] ciphertext = (byte[])message.getObjContents().get(0);
						byte[] m1Decrypted = (byte[])crypto.rsaDecrypt(ciphertext, privateFSKey);

						byte[] userNonceDecrypted = Arrays.copyOfRange(m1Decrypted, 0, 32);
						byte[] keyDecrypted = Arrays.copyOfRange(m1Decrypted, 32, 64);
						// System.out.println("AES Key Bytes: " + Arrays.toString(keyDecrypted));
						byte[] keyHmacBytes = Arrays.copyOfRange(m1Decrypted, 64, 96);
						byte[] iv = Arrays.copyOfRange(m1Decrypted, 96, m1Decrypted.length);
						// System.out.println("IV decrypted: " + Arrays.toString(iv));

						crypto = new Crypto(iv);
						//Test statements
						System.out.println("Received message 1 trying to authenticate:");

						//Step 2 - RESPONSE from server

						//generate new challenge and response to the challenge
						fileNonce = crypto.generateNonce(256);

						//response to the challenge from user
						byte[] userNonceResponse = generateNonceResponse(userNonceDecrypted);

						sharedKey = new SecretKeySpec(keyDecrypted, 0, keyDecrypted.length, "AES");
						hmacKey = new SecretKeySpec(keyHmacBytes, 0, keyHmacBytes.length, "AES");

						// verify integrity

						byte[] hmac = (byte[]) message.getObjContents().get(1);
						if (!crypto.verifyHmac(hmac, ciphertext, hmacKey)) {
							System.out.println("Invalid HMAC of encrypted message! Message may have been tampered with! ");
							System.out.println("Will terminate connection now.");
							response = new Envelope("FAIL-BAD_HMAC");
							output.writeObject(response);
							output.close();
							input.close();
							socket.close(); //Close the socket
							proceed = false;
							continue;
						}
						System.out.println("Envelope integrity verified with HMAC.");

						System.out.println("Sending message 2 to client.");

						// response consists of challenge response and new challenge to client
						response = new Envelope("OK");
						response.addObject(userNonceResponse);
						response.addObject(fileNonce);

						// serialize envelope and then encrypt
						byte[] envelopeBytes = FileClient.serialize(response);
						byte[] cipher = crypto.aesEncrypt(envelopeBytes, sharedKey);

						// generate hmac and put encrypted envelope and hmac inside wrapper envelope
						hmac = crypto.hmac(cipher, hmacKey);
						Envelope wrapper = new Envelope("AES");
						wrapper.addObject(cipher);
						wrapper.addObject(hmac);
						// send
						output.writeObject(wrapper);
						authenticate1 = true;

						// Start message counters at 0 after file server authentication phase complete
						incomingCount = 0;
						outgoingCount = 0;
					}
					catch(Exception e){
						System.out.println("Invalid formatting of message 1.");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
				}

				else if(message.getMessage().equals("LFILES")) {

					// Check to make sure parameters are passed and not null
					if (message.getObjContents().size() < 3){
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else {

						// list to hold the files the requester can see
						response = new Envelope("OK");
						List<String> list = new ArrayList<>();

						/* Iterate over group in the requestor's token and find all files for that group
						 Add groupName:fileName string to list of files for reply */
						for (String g : token.getGroups()){
					  	for (int i = 0; i < FileServer.fileList.getFiles().size(); i++){
							  if (FileServer.fileList.getFiles().get(i).getGroup().equals(g)){
							    String fileName = g + ": " + FileServer.fileList.getFiles().get(i).getPath();
									//String fileName = FileServer.fileList.getFiles().get(i).getPath();
									list.add(fileName);
						    }
						  }
					  }
						// add list to response envelope
						response.addObject(list);
				}


				Envelope wrapper = packageResponse(response);
				output.writeObject(wrapper);

				}
				if(message.getMessage().equals("UPLOADF"))
				{

					if(requestParams.length < 2)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						String remotePath = requestParams[0];
						String group = requestParams[1];
						if(remotePath == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(group == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(token == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = new Envelope("FAIL-FILEEXISTS"); //Success
							}
							else if (!token.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = new Envelope("FAIL-UNAUTHORIZED"); //Success
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); //Success
								Envelope wrapper = packageResponse(response);
								output.writeObject(wrapper);

								// Get response from client
								wrapper = (Envelope)input.readObject();
								message = extractRequest(wrapper, output, input, false);

								while (message.getMessage().compareTo("CHUNK")==0) {
									// decrypt message stored in envelope as first object
									// byte[] decryptedBuf = decryptMessage(message);

									// write to buffer. third envelope object has length of decrypted buffer
									fos.write((byte[])message.getObjContents().get(1), 0, (Integer)message.getObjContents().get(2));
									response = new Envelope("READY"); //Success
									wrapper = packageResponse(response);
									output.writeObject(wrapper);

									// Get response from client
									wrapper = (Envelope)input.readObject();
									message = extractRequest(wrapper, output, input, false);
								}

								if(message.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(token.getSubject(), group, remotePath);
									response = new Envelope("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); //Success
								}
								fos.close();
							}
						}
					}

					Envelope wrapper = packageResponse(response);
					output.writeObject(wrapper);
				}
				else if (message.getMessage().compareTo("DOWNLOADF")==0) {

					String[] params = (String[])message.getObjContents().get(2);

					String remotePath = params[0];
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						message = new Envelope("ERROR_FILEMISSING");
						Envelope wrapper = packageResponse(message);
						output.writeObject(wrapper);

					}
					else if (!token.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", token.getSubject());
						message = new Envelope("ERROR_PERMISSION");
						Envelope wrapper = packageResponse(message);
						output.writeObject(wrapper);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							message = new Envelope("ERROR_NOTONDISK");
							Envelope wrapper = packageResponse(message);
							output.writeObject(wrapper);
						}
						else {
							FileInputStream fis = new FileInputStream(f);

							do {
								byte[] buf = new byte[4096];
								if (message.getMessage().compareTo("DOWNLOADF")!=0) {
									System.out.printf("Server error: %s\n", message.getMessage());
									break;
								}
								message = new Envelope("CHUNK");
								int n = fis.read(buf); //can throw an IOException
								if (n > 0) {
									System.out.printf(".");
								} else if (n < 0) {
									System.out.println("Read error");

								}
								// encrypt buffer before sending
								// byte[] encryptedBuf = crypto.aesEncrypt(buf, sharedKey);

								message.addObject(buf);
								// add size of buffer
								message.addObject(new Integer(n));

								Envelope wrapper = packageResponse(message);
								output.writeObject(wrapper);

								// Get response from client
								wrapper = (Envelope)input.readObject();
								message = extractRequest(wrapper, output, input, false);

							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(message.getMessage().compareTo("DOWNLOADF")==0)
							{

								message = new Envelope("EOF");
								Envelope wrapper = packageResponse(message);
								output.writeObject(wrapper);

								// Get response from client
								wrapper = (Envelope)input.readObject();
								message = extractRequest(wrapper, output, input, false);

								if(message.getMessage().compareTo("OK")==0) {
									System.out.printf("File data upload successful\n");
								}
								else {

									System.out.printf("Upload failed: %s\n", message.getMessage());

								}

							}
							else {

								System.out.printf("Upload failed: %s\n", message.getMessage());

							}
							fis.close();
						}

						}
						catch(Exception e1)
						{
							System.err.println("Error: " + message.getMessage());
							e1.printStackTrace(System.err);

						}
					}

				}
				else if (message.getMessage().compareTo("DELETEF")==0) {

					String[] params = (String[])message.getObjContents().get(2);

					String remotePath = params[0];
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					System.out.println("Trying to delete a file from group: " + sf.getGroup());
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						message = new Envelope("ERROR_DOESNTEXIST");
					}
					else if (!token.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", token.getSubject());
						message = new Envelope("ERROR_PERMISSION");
					}
					else {
						System.out.println("User belongs to group!");
						try
						{
							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								message = new Envelope("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								message = new Envelope("OK");
							}
							else {
								System.out.println("Test point.");
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								message = new Envelope("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							message = new Envelope(e1.getMessage());
						}
					}
					Envelope wrapper = packageResponse(message);
					output.writeObject(wrapper);

				}
				else if(message.getMessage().equals("DISCONNECT"))
				{
					socket.close();
					proceed = false;
				}
				//shutdown??
				else if (message.getMessage().equals("DISCONNECT and SHUTDOWN")){
					//System.out.println("SHUTDOWN SERVER!!!!!!!!!!");
					socket.close(); //Close the socket
					proceed = false;
					System.exit(0);
				}
			} while(proceed);
		}
		catch(Exception message)
		{
			System.err.println("Error: " + message.getMessage());
			message.printStackTrace(System.err);
		}
	}

	private boolean verifyNonceResponse(byte[] response){
		System.out.print("Testing to see if user's challenge response is accurate.");
		BigInteger fileNonceBigInt = new BigInteger(fileNonce);
		fileNonceBigInt = fileNonceBigInt.subtract(BigInteger.valueOf(1));
		BigInteger fileNonceResponse = new BigInteger(response);
		if(fileNonceBigInt.equals(fileNonceResponse)){
			System.out.println(" Success!");
			return true;
		}
		else{
			System.out.println(" Failure!");
			return false;
		}
	}

	private byte[] generateNonceResponse(byte[] original){
			System.out.println("Computing response to challenge.");
			BigInteger responseBigInt = new BigInteger(original);		//computing R1-1
			responseBigInt = responseBigInt.subtract( BigInteger.valueOf(1) );
			byte[] nonceResponse = responseBigInt.toByteArray();
			return nonceResponse;
	}


	public boolean verifySignature(UserToken token) {
		byte[] sig = token.getSignature();
		byte[] hashedToken = crypto.hashSHA_256(token.toString());
		boolean verify1 = crypto.verifyRSASig(hashedToken, sig, gsKey);
		byte[] myPubKeyHash = crypto.hashSHA_256(publicFSKey.getEncoded());
		//System.out.println("My Hash:" + Arrays.toString(myPubKeyHash));
		//System.out.println("Token's:" + Arrays.toString(token.getFileServerID()));
		System.out.print("Verifying Token's FSKeyHash: ");
		boolean verify2 = false;
		if(Arrays.equals(myPubKeyHash, token.getFileServerID())){
			System.out.println("Success!");
			verify2 = true;
		}
		else{
			System.out.println("Failed!");
		}
		return (verify1 && verify2);
	}

	/* Takes wrapper envelope, socket input/output streams, and parameters flag.
		Checks to see if counter is correct. Check nonce response if not yet
		verified. Checks token. If any check fails, closes socket and streams
		after returning a failure message in an envelope.
		If parameters exist, global requestParams variable is updated */
	public Envelope extractRequest(Envelope wrapper, ObjectOutputStream output, ObjectInputStream input, boolean paramsExist) {

		byte[] envelopeCipherBytes = (byte[]) wrapper.getObjContents().get(0);
		byte[] hmac = (byte[]) wrapper.getObjContents().get(1);

		// Check to see if HMAC is valid
		boolean valid = crypto.verifyHmac(hmac, envelopeCipherBytes, hmacKey);
		if (!valid){
			System.out.println("Invalid HMAC! Message may have been altered, so envelope contents will be discarded.");
			Envelope response = new Envelope("FAIL-BAD_HMAC");
			try{
				output.writeObject(response);
				output.close();
				input.close();
				socket.close(); //Close the socket
				return null;
			}
			catch (Exception ex) {				}
			return null;
		}
		System.out.println("Envelope integrity verified with HMAC.");

		// Decrypt inner envelope since its integrity is verified
		byte[] envelopePlain  = (byte[]) crypto.aesDecrypt(envelopeCipherBytes, sharedKey);
		Envelope e = (Envelope)FileClient.deserialize(envelopePlain);
		Integer messageCount = (Integer)e.getObjContents().get(0);
		System.out.println("Received message #" + messageCount + ": " + e.getMessage());
		// Check counter
		if (messageCount != (incomingCount)){
			Envelope response = new Envelope("FAIL-MESSAGE_ORDER");
			try{
				output.writeObject(response);
				output.close();
				input.close();
				socket.close(); //Close the socket--failed message count
			}
			catch (Exception ex) {				}
		}
		System.out.println("Message order verified.");
		incomingCount++;

		// Check nonce response, if needed
		// This will close the socket if it fails
		if (!authenticate2) authenticate2(e, output, input);

		// Check token
		if (!user_authenticated){
			token = (UserToken)e.getObjContents().get(1);
			user_authenticated = verifySignature(token);
			if (!user_authenticated){
				Envelope response = new Envelope("FAIL-INVALID TOKEN");
				try{
					output.writeObject(response);
					output.close();
					input.close();
					socket.close(); //Close the socket
				}
				catch (Exception ex) {				}
			}
		}

		// Extract parameters
		if (paramsExist)
			requestParams = (String[])e.getObjContents().get(2);

		return e;
	}

	/* Verifies the nonce response. This should only take place with first request
		sent to server after the file server has authenticated to user.  */
	public void authenticate2(Envelope e, ObjectOutputStream output, ObjectInputStream input) {
			byte[] userNonceResponse = (byte[]) e.getObjContents().get(3);
			authenticate2 = verifyNonceResponse(userNonceResponse);
			if (!authenticate2){
				Envelope response = new Envelope("FAIL-AUTH");
				try{
					output.writeObject(response);
					output.close();
					input.close();
					socket.close(); //Close the socket
				}
				catch (Exception ex) {				}
				System.exit(-1);
			}
	}

	/* Add message counter as first object in envelope. Encrypt envelope and place inside wrapper.
		Add hmac of encrypted envelope to wrapper envelope.
		*/
	public Envelope packageResponse(Envelope e) {
		e.getObjContents().add(0, (Integer)outgoingCount);
		outgoingCount++;

		byte[] envelopeBytes = FileClient.serialize(e);
		byte[] ciphertextBytes = crypto.aesEncrypt(envelopeBytes, sharedKey);
		byte[] hmac = crypto.hmac(ciphertextBytes, hmacKey);

		Envelope wrapper = new Envelope("AES");
		wrapper.addObject(ciphertextBytes);
		wrapper.addObject(hmac);
		return wrapper;
	}



}
