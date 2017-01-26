/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.math.*;

public class FileThread extends Thread
{
	private final Socket socket;
	private       FileServer my_fs;
	private Crypto crypto;
	//private boolean authenticate1 = false;
	private Key publicFSKey;
	private Key privateFSKey;
	private PublicKey gsKey;
	private byte[] fileNonce;
	private byte[] fileNonceResponse;
	private byte[] userNonce;
	private Key sharedKey;
	private boolean authenticate1 = false;
	private boolean user_authenticated = false;
	private String[] requestParams;
	private UserToken token;




	public FileThread(Socket _socket, FileServer _fs)
    {
        socket = _socket;
        my_fs  = _fs;
				crypto = new Crypto();
				publicFSKey = my_fs.getFSpublicKey();
				privateFSKey = my_fs.getFSprivateKey();
				gsKey = my_fs.getGSKey();

    }


	public void run()
	{
		boolean proceed = true;
		try{ // Establish a connection, create input and output streams

			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());



			do
			{
				System.out.println();
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				// Handler to list files that this user is allowed to see

				//Client wants FileServer's public key
				if(message.getMessage().equals("GETKEY")){
					response = new Envelope("OK");
					response.addObject(publicFSKey);
					output.writeObject(response);
				}
				else if (message.getMessage().equals("AUTHENTICATE1")){
					try{
						//extract the encrypted message
						byte[] m1Encrypted = (byte[])message.getObjContents().get(0);
						//decrypt it
						byte[] m1Decrypted = crypto.rsaDecrypt(m1Encrypted, privateFSKey);

						byte[] userNonceDecrypted = Arrays.copyOfRange(m1Decrypted, 0,m1Decrypted.length-32);
						byte[] keyDecrypted = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length-32,m1Decrypted.length-16);
						System.out.println("AES Key Bytes: " + Arrays.toString(keyDecrypted));
						byte[] iv = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length- 16, m1Decrypted.length);
						System.out.println("IV decrypted: " + Arrays.toString(iv));
						crypto = new Crypto(iv);
						//Test statements
						System.out.println("Received message 1 trying to authenticate:");

						//Step 2 - RESPONSE from server

						//generate new challenge and response to the challenge
						fileNonce = crypto.generateNonce(256);

						//response to the challenge from user
						byte[] userNonceResponse = generateNonceResponse(userNonceDecrypted);

						//put all parts together to form: {R1-1 || R2}
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
						try{
							outputStream.write(userNonceResponse);
							outputStream.write(fileNonce);
						}
						catch(Exception e){
							System.out.println("Error with ByteArrayOutputStream");
							System.exit(0);
						}
						byte message2[] = outputStream.toByteArray( );

						//Encrypt it
						sharedKey = new SecretKeySpec(keyDecrypted, 0, keyDecrypted.length, "AES");

						//Note: Key was converted into bytes before for transfer, need to re-encode
						byte[] m2Encrypted = crypto.aesEncrypt(message2, sharedKey);

						//System.out.println("Message 2 Encrypted length: " + m2Encrypted.length);
						System.out.println("Sending message 2 to client.");

						//add it and send it back
						response = new Envelope("OK");
						response.addObject(m2Encrypted);
						output.writeObject(response);
						authenticate1 = true;
					}
					catch(Exception e){
						System.out.println("Invalid formatting of message 1.");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}

				}

				else if(message.getMessage().equals("LFILES"))
				{
					 // Check to make sure parameters are passed and != null
					if (message.getObjContents().size() < 2 || message.getObjContents().get(0) == null){
						response = packageResponse("FAIL-BADCONTENTS");
						output.writeObject(response);

					}
					else
					{
						Integer paramsLength = (Integer)message.getObjContents().get(1);
						System.out.println("Param length from FileThread.LFILES" + paramsLength);

						// decrypt byte array stored as first object in envelope
						byte[] decryptedMsg = decryptMessage(message);

						// extract parameters, token, and nonces;
						extractRequest(decryptedMsg, (int)paramsLength);
						user_authenticated = authenticate2(fileNonceResponse);
						// byte[] userNonceResponse = generateNonceResponse(userNonce);
						// fileNonce = crypto.generateNonce(256);
						// byte[] concatNonces = new byte[64];
						// System.out.println("length of userNonce"  + userNonce.length);
						// System.out.println("length of usreNonceRepsonse" + userNonceResponse.length);
						// System.out.println("length fo fileNonce" + fileNonce.length);
						// System.arraycopy(userNonceResponse, 0, concatNonces, 0, 32);
						// System.arraycopy(fileNonce, 0, concatNonces, 32, 32);

						if (!user_authenticated) {
							response = packageResponse("FAIL-UNAUTH");
							output.writeObject(response);
						}
						else {
							// list to hold the files the requester can see
							List<String> list = new ArrayList<>();
							// Iterate over each file and check against requester's groups
							// TODO: probably a better way to do this and need to account for ADMIN group
							for (int i = 0; i < FileServer.fileList.getFiles().size(); i++)
							for (int j = 0; j < token.getGroups().size(); j++)
							if (FileServer.fileList.getFiles().get(i).getGroup().equals(token.getGroups().get(j)))
							list.add(FileServer.fileList.getFiles().get(i).getPath());
							// If list is created, change response to OK
							// response = new Envelope("OK");
							response = packageResponse("OK", list);

						}
						// Send response
					}
					output.writeObject(response);

				}
				if(message.getMessage().equals("UPLOADF"))
				{
					// decrypt message stored as first object in envelope
					byte[] decryptedMsg = decryptMessage(message);
					Integer paramsLength = (Integer) message.getObjContents().get(1);

					// extract nonces, token, and params, and update globals
					extractRequest(decryptedMsg, paramsLength);
					user_authenticated = authenticate2(fileNonceResponse);


					if (!user_authenticated) {
						response = packageResponse("FAIL-UNAUTH");

					}

					String dest = requestParams[0];

					if(requestParams.length < 2)
					{
						response = packageResponse("FAIL-BADCONTENTS");
					}
					else
					{
						String remotePath = requestParams[0];
						String group = requestParams[1];
						if(remotePath == null) {
							response = packageResponse("FAIL-BADPATH");
						}
						if(group == null) {
							response = packageResponse("FAIL-BADGROUP");
						}
						if(token == null) {
							response = packageResponse("FAIL-BADTOKEN");
						}
						else {

							if (FileServer.fileList.checkFile(remotePath)) {
								System.out.printf("Error: file already exists at %s\n", remotePath);
								response = packageResponse("FAIL-FILEEXISTS");
							}
							else if (!token.getGroups().contains(group)) {
								System.out.printf("Error: user missing valid token for group %s\n", group);
								response = packageResponse("FAIL-UNAUTHORIZED");
							}
							else  {
								File file = new File("shared_files/"+remotePath.replace('/', '_'));
								file.createNewFile();
								FileOutputStream fos = new FileOutputStream(file);
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = packageResponse("READY"); //Success
								output.writeObject(response);

								// Get response from client
								message = (Envelope)input.readObject();
								while (message.getMessage().compareTo("CHUNK")==0) {
									// decrypt message stored in envelope as first object
									byte[] decryptedBuf = decryptMessage(message);
									// write to buffer. second envelope object has length of decrypted buffer
									fos.write(decryptedBuf, 0, (Integer)message.getObjContents().get(1));
									response = packageResponse("READY"); //Success
									output.writeObject(response);
									message = (Envelope)input.readObject();
								}

								if(message.getMessage().compareTo("EOF")==0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(token.getSubject(), group, remotePath);
									response = packageResponse("OK"); //Success
								}
								else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = packageResponse("ERROR-TRANSFER");

								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				}
				else if (message.getMessage().compareTo("DOWNLOADF")==0) {

					// decrypt message stored in envelope as first object
					byte[] decryptedMsg = decryptMessage(message);
					Integer paramsLength = (Integer) message.getObjContents().get(1);

					// extract nonces, params, and token and update globals
					extractRequest(decryptedMsg, paramsLength);
					user_authenticated = authenticate2(fileNonceResponse);

					if (!user_authenticated) {
						response = packageResponse("FAIL-UNAUTH");
						output.writeObject(response);
					}

					String remotePath = requestParams[0];
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						message = packageResponse("ERROR_FILEMISSING");
						output.writeObject(message);

					}
					else if (!token.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", token.getSubject());
						message = packageResponse("ERROR_PERMISSION");
						output.writeObject(message);
					}
					else {

						try
						{
							File f = new File("shared_files/_"+remotePath.replace('/', '_'));
						if (!f.exists()) {
							System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
							message = packageResponse("ERROR_NOTONDISK");
							output.writeObject(message);

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
								byte[] encryptedBuf = crypto.aesEncrypt(buf, sharedKey);

								message.addObject(encryptedBuf);
								// add size of buffer
								message.addObject(new Integer(n));

								output.writeObject(message);

								// Get response from client
								message = (Envelope)input.readObject();


							}
							while (fis.available()>0);

							//If server indicates success, return the member list
							if(message.getMessage().compareTo("DOWNLOADF")==0)
							{

								message = new Envelope("EOF");
								output.writeObject(message);

								message = (Envelope)input.readObject();
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

					// decrypt message
					byte[] decryptedMsg = decryptMessage(message);
					Integer paramsLength = (Integer)message.getObjContents().get(1);
					// extract nonces, params, and token and update global nonce and token
					extractRequest(decryptedMsg, (int)paramsLength);
					user_authenticated = authenticate2(fileNonceResponse);
					String remotePath = "";

					if (!user_authenticated) {
						response = packageResponse("FAIL-AUTH");
						output.writeObject(response);
					}
					else {
						remotePath = requestParams[0];
					}
					ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
					System.out.println("Trying to delete a file from group: " + sf.getGroup());
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						message = packageResponse("ERROR_DOESNTEXIST");
					}
					else if (!token.getGroups().contains(sf.getGroup())){
						System.out.printf("Error user %s doesn't have permission\n", token.getSubject());
						message = packageResponse("ERROR_PERMISSION");
					}
					else {
						System.out.println("User belongs to group!");
						try
						{
							File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
								message = packageResponse("ERROR_FILEMISSING");
							}
							else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/"+remotePath);
								message = packageResponse("OK");
							}
							else {
								System.out.println("Test point.");
								System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
								message = packageResponse("ERROR_DELETE");
							}


						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							message = new Envelope(e1.getMessage());
						}
					}
					output.writeObject(message);

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

	// request should already have been extracted and global token field updated before this
	private boolean authenticate2(byte[] nonceResponse) {
		boolean authenticate2 = false;
		byte[] hashedToken = crypto.hashSHA_256(token.toString());
		byte[] signature = token.getSignature();
		boolean validSig = crypto.verifyRSASig(hashedToken, signature, gsKey);
		System.out.println("Token has valid signature from group server: " + validSig);
		//test to see if response to fileNonce is accurate
		//Note: verifyNonceResponse method takes in byte array and validates against fileNonce stored in this class
		boolean nonceVerified = verifyNonceResponse(nonceResponse);
		if (!nonceVerified){
			System.out.println("Invalid nonce.");
		}
		else if (!validSig){
			System.out.println("Invalid token signature.");
		}
		else {
				authenticate2 = true;
		}
		return authenticate2;
	}

	public byte[] decryptMessage(Envelope message) {
			byte[] mEncrypted = (byte[])message.getObjContents().get(0);
			byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
			return mDecrypted;

	}


	//This updates the global fields token, fileNonceResponse, userNonce, and requestParams which is a String[]
	private  void extractRequest(byte[] message, int paramLength) {
		System.out.println("Message length " + message.length);
		fileNonceResponse = Arrays.copyOfRange(message, 0, 32);
		// only continue if nonce is verified
		if (verifyNonceResponse(fileNonceResponse)){
			userNonce = Arrays.copyOfRange(message, 32, 64);
			byte[] subArray = Arrays.copyOfRange(message, 64, message.length);
			byte[] tokenBytes;
			if (paramLength == 0) {
				System.out.println("No params to extract");
				tokenBytes = Arrays.copyOfRange(subArray, 0, subArray.length);
			}

			else {
				byte[] params  = Arrays.copyOfRange(subArray, 0, paramLength);
				requestParams = (String[])(FileClient.deserialize(params));
				tokenBytes = Arrays.copyOfRange(subArray, paramLength, subArray.length);
				System.out.println("token len " + (subArray.length-paramLength));
			}
			UserToken tempToken = (UserToken)crypto.deserializeToken(tokenBytes);
			token = tempToken.deepCopy(tempToken);
			// System.out.println("token sig after extraction " + Arrays.toString(token.getSignature()));
		}
		else {
			System.out.println("at FileThread.extractRequest(): invalid fileNonce" );
		}
	}


	private Envelope packageResponse(String message, List<String> list) {
		Envelope e = new Envelope(message);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] fileNonceResponse = generateNonceResponse(userNonce);
		// generate new nonce challenge for file server
		fileNonce = crypto.generateNonce(256);
		byte[] listBytes = FileClient.serialize(list);
		try {
			outputStream.write(fileNonceResponse);
			outputStream.write(fileNonce);
			outputStream.write(listBytes);
		}
		catch (Exception ex) {
			System.out.println("problem packaging response");
			return null;
		}
		byte[] responseBytes = outputStream.toByteArray();
		byte[] encryptedResponse = crypto.aesEncrypt(responseBytes, sharedKey);
		e.addObject(encryptedResponse); // Add the list and nonces
		e.addObject((Integer)0); // params length is 0
		return e;
	}


	private Envelope packageResponse(String message) {
		Envelope e = new Envelope(message);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		byte[] fileNonceResponse = generateNonceResponse(userNonce);
		// generate new nonce challenge for file server
		fileNonce = crypto.generateNonce(256);
		try {
			outputStream.write(fileNonceResponse);
			outputStream.write(fileNonce);
		}
		catch (Exception ex) {
			System.out.println("problem packaging response");
			return null;
		}
		byte[] responseBytes = outputStream.toByteArray();
		byte[] encryptedResponse = crypto.aesEncrypt(responseBytes, sharedKey);
		e.addObject(encryptedResponse); // Add the nonces
		e.addObject((Integer)0); // params length is 0
		return e;
	}





}
