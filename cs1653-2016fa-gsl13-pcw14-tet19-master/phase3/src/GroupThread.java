/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.security.*;
import java.nio.charset.*;
import java.math.*;
import javax.crypto.spec.*;

public class GroupThread extends Thread
{
	private final static byte[] nullspace = new byte[]{(byte)0x00};
	private final Socket socket;
	private GroupServer my_gs;
	private Crypto crypto;
	private boolean authenticate1 = false;
	private boolean user_authenticated = false;
	private PublicKey publicGSKey;
	private PrivateKey privateGSKey;
	private String user;
	private byte[] userNonce;
	private byte[] groupNonce;
	private Key sharedKey;

	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		crypto = new Crypto();
		publicGSKey = my_gs.database.getPublicKey();
		privateGSKey = my_gs.database.getPrivateKey();
		//if(publicGSKey == null) System.out.println("Group Thread: Problem getting public key!");
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
				System.out.println();
				Envelope message = (Envelope)input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				//Client wants GroupServer's public key
				if(message.getMessage().equals("GETKEY")){
					response = new Envelope("OK");
					response.addObject(publicGSKey);
					output.writeObject(response);
				}

				//Step 1 of authentication
				else if(message.getMessage().equals("AUTHENTICATE1")){
					try{
						//extract the encrypted message
						byte[] m1Encrypted = (byte[])message.getObjContents().get(0);
						//decrypt it
						byte[] m1Decrypted = crypto.rsaDecrypt(m1Encrypted, privateGSKey);
						//Extract all the parts
						byte[] usernameDecrypted = Arrays.copyOfRange(m1Decrypted, 0, m1Decrypted.length-64);
						String usernameDecryptedString = new String(usernameDecrypted, StandardCharsets.UTF_8);
						user = usernameDecryptedString;
						byte[] userNonceDecrypted = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length-64,m1Decrypted.length-32);
						byte[] keyDecrypted = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length-32,m1Decrypted.length-16);
						//System.out.println("AES Key Bytes: " + Arrays.toString(keyDecrypted));
						byte[] iv = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length- 16, m1Decrypted.length);
						//System.out.println("IV decrypted: " + Arrays.toString(iv));
						crypto = new Crypto(iv);
						//Test statements
						System.out.println("Received message 1 trying to authenticate:");
						System.out.println("Username: " + usernameDecryptedString);
						if(!my_gs.database.checkItemExists(usernameDecryptedString)){
							System.out.println("User does not exist in database!");
							response = new Envelope("FAIL");
							response.addObject(null);
							output.writeObject(response);
						}
						else{
							//Step 2 - RESPONSE from server
							//generate new challenge and response to the challenge
							groupNonce = crypto.generateNonce(256);
							//responsd to the challenge from user
							byte[] userNonceResponse = generateNonceResponse(userNonceDecrypted);
							//put all parts together to form: {R1-1 || R2}
							ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							try{
								outputStream.write(userNonceResponse);
								outputStream.write(groupNonce);
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
					}
					catch(Exception e){
						System.out.println("Invalid formatting of message 1.");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
				}

				//STEP 3 -
				else if(message.getMessage().equals("AUTHENTICATE2")){
					try{
						if(authenticate1){
							//extract the encrypted message
							byte[] m3Encrypted = (byte[])message.getObjContents().get(0);
							//Decrypt it
							byte[] m3Decrypted = crypto.aesDecrypt(m3Encrypted, sharedKey);
							//Extract all parts
							byte[] groupNonceResponseDecrypted = Arrays.copyOfRange(m3Decrypted,0,32);
							byte[] passwordBytesDecrypted = Arrays.copyOfRange(m3Decrypted,32,m3Decrypted.length);

							//test to see if response to groupNonce is accurate
							if(!verifyNonceResponse(groupNonceResponseDecrypted)){
								//Note: verifyNonceResponse method takes in byte array and validates against groupNonce stored in this class
								System.out.println("Invalid nonce.");
								response = new Envelope("FAIL");
								response.addObject(null);
								output.writeObject(response);
							}
							else{
								System.out.println("Received message 3 from client.");
								//match username and password against DB
								System.out.println("Testing to see if user's username and password are valid");
								String pass =  new String(passwordBytesDecrypted, StandardCharsets.UTF_8);
								if(my_gs.database.checkItem(user, pass)){
									System.out.println("Success!");
									//create and send the token back
									UserToken yourToken = createToken(user); 			//Create a token
									UserToken tokenCopy = yourToken.deepCopy(yourToken);		//Create Deep Copy of token
									//generate new nonce for next message
									groupNonce = crypto.generateNonce(256);
									//serialize and encrypt the token
									byte[] tokenBytes = crypto.serializeToken((Token)tokenCopy);
									ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
									try{
										outputStream.write(tokenBytes);
										outputStream.write(groupNonce);
									}
									catch(Exception e){
										System.out.println("Error with ByteArrayOutputStream");
										System.exit(0);
									}
									byte message4[] = outputStream.toByteArray( );
									byte[] m4Encrypted = crypto.aesEncrypt(message4, sharedKey);


									//Respond to the client. On error, the client will receive a null token
									response = new Envelope("OK");
									response.addObject(m4Encrypted);
									output.writeObject(response);

									System.out.println("User has been authenticated. Sending token!");
									user_authenticated = true;
								}
								else{
									System.out.println("Failure! Username and password pair invalid");
									response = new Envelope("FAIL");
									response.addObject(null);
									output.writeObject(response);
								}
							}
						}
						else{
							System.out.println("Need to run authenticate1 first.");
							response = new Envelope("FAIL");
							response.addObject(null);
							output.writeObject(response);
						}
					} catch(Exception e){
						System.out.println("Something went wrong. Invalid format of message 3.");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
				}

				//---------------------------------------------------------------------------------
				else if(message.getMessage().equals("GET"))//Client wants a token
				{
					System.out.println("Trying to get a new token for " + user);
					//extract and decrypt response
					byte[] mEncrypted = (byte[])message.getObjContents().get(0);
					byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
					//extract components
					userNonce = Arrays.copyOfRange(mDecrypted, 0, 32);
					byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 32, 64);

					if(verifyNonceResponse(groupNonceResponse)){
							if(!user_authenticated){
								System.out.println("User is not authenticated. Returning fail.");
								response = new Envelope("FAIL");
								response.addObject("NOTAUTHENTICATED");
								output.writeObject(response);
							}
							else{
								//generate components
								System.out.println("Creating token, user was authenticated");
								UserToken yourToken = createToken(user); 			//Create a token
								UserToken tokenCopy = yourToken.deepCopy(yourToken);		//Create Deep Copy of token
								//make new group nonce
								groupNonce = crypto.generateNonce(256);
								//make nonce response
								byte[] userNonceResponse = generateNonceResponse(userNonce);

								//put it all together
								ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
								outputStream.write(groupNonce);
								outputStream.write(userNonceResponse);
								outputStream.write(crypto.serializeToken((Token)tokenCopy));
								byte[] r = outputStream.toByteArray();
								//encrypt it
								byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);

								//Respond to the client. On error, the client will receive a null token
								response = new Envelope("OK");
								response.addObject(rEncrypted);
								output.writeObject(response);
								System.out.println("Sending response with token back to client");
							}
					}
					else{
						System.out.println("User's response to challenge nonce failed.");
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					}
				}
				//-----------------------------------------------------------------------------------------
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
				{
					System.out.println(user + " is trying to create a new user.");
					try{
						byte[] mEncrypted = (byte[])message.getObjContents().get(0);
						byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);

						byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
						if(!verifyNonceResponse(groupNonceResponse)){
							System.out.println("User did not pass nonce response challenge");
						}
						else{	//user passed nonce response challenge
							userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
							byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
							int[] indexes = findNullIndex(subArray, 2);
							//System.out.println("Null indexes at: " + indexes[0] + " and " + indexes[1]);
							byte[] usernameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]); //Extract the username
							String username = new String(usernameBytes, StandardCharsets.UTF_8);
							byte[] passwordBytes = Arrays.copyOfRange(subArray, indexes[0]+1, indexes[1]);//Extract the password
							String password = new String(passwordBytes, StandardCharsets.UTF_8);
							byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[1]+1, subArray.length); //Extract the token
							Token yourToken = (Token)crypto.deserializeToken(tokenBytes);
						//	System.out.println("Token received: " + yourToken.toString());
							System.out.println("Trying to create user: " + username + " with password: " + password);
							if(createUser(username, yourToken))
							{
								System.out.println("Trying to add new username/password to database.");
								if(my_gs.database.addItem(username, password)){
									response = new Envelope("OK"); //Success
									byte[] userNonceResponse = generateNonceResponse(userNonce);
									groupNonce = crypto.generateNonce(256);
									ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
										outputStream.write(userNonceResponse);
										outputStream.write(groupNonce);
									byte[] r = outputStream.toByteArray( );
									byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
									System.out.println("Sending back OK response");
									response.addObject(rEncrypted);
									output.writeObject(response);
									continue;
								}
							}
							else{
								System.out.println("User already exists or token owner is not admin.");
							}
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}
					catch(Exception e){
						System.out.println("Something failed when trying to create user.");
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}

				}
				//-------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					System.out.println(user + " is trying to delete a user.");
					try{
						byte[] mEncrypted = (byte[])message.getObjContents().get(0);
						byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
						byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
						if(!verifyNonceResponse(groupNonceResponse)){
							System.out.println("User did not pass nonce response challenge");
						}
						else{	//user passed nonce response challenge
							userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
							byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
							int[] indexes = findNullIndex(subArray, 1);
							//extract components
							byte[] usernameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]);//Extract the password
							String username = new String(usernameBytes, StandardCharsets.UTF_8);
							byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[0]+1, subArray.length); //Extract the token
							Token yourToken = (Token)crypto.deserializeToken(tokenBytes);
							System.out.println("Trying to delete user: " + username);
								if(deleteUser(username, yourToken))
								{
									//delete it from database too
									if(my_gs.database.deleteItem(username)){
										response = new Envelope("OK"); //Success
										byte[] userNonceResponse = generateNonceResponse(userNonce);
										groupNonce = crypto.generateNonce(256);
										ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
											outputStream.write(userNonceResponse);
											outputStream.write(groupNonce);
										byte[] r = outputStream.toByteArray( );
										byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
										System.out.println("Sending back OK response.");
										response.addObject(rEncrypted);
										output.writeObject(response);
										continue;
									}
								}
						}
					}
					catch(Exception e){
						System.out.println("Something failed when trying to create user.");
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}
					response = new Envelope("FAIL"); //something didn't work
					byte[] userNonceResponse = generateNonceResponse(userNonce);
					groupNonce = crypto.generateNonce(256);
					ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
						outputStream.write(userNonceResponse);
						outputStream.write(groupNonce);
					byte[] r = outputStream.toByteArray( );
					byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
					System.out.println("Sending back FAIL response.");
					response.addObject(rEncrypted);
					output.writeObject(response);
				}
				//----------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
						System.out.println(user + " is trying to create a group.");
						try{
							byte[] mEncrypted = (byte[])message.getObjContents().get(0);
							byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
							byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
							if(!verifyNonceResponse(groupNonceResponse)){
								System.out.println("User did not pass nonce response challenge");
							}
							else{	//user passed nonce response challenge
								userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
								byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
								int[] indexes = findNullIndex(subArray, 1);
								//extract components
								byte[] groupnameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]);//Extract the password
								String groupname = new String(groupnameBytes, StandardCharsets.UTF_8);
								byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[0]+1, subArray.length); //Extract the token
								Token token = (Token)crypto.deserializeToken(tokenBytes);
								System.out.println("Trying to delete group: " + groupname);
								//create group will return true or false depending on success of creating group
									if(createGroup(groupname, token))
									{
										response = new Envelope("OK"); //Success
										byte[] userNonceResponse = generateNonceResponse(userNonce);
										groupNonce = crypto.generateNonce(256);
										ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
											outputStream.write(userNonceResponse);
											outputStream.write(groupNonce);
										byte[] r = outputStream.toByteArray( );
										byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
										System.out.println("Sending back OK response.");
										response.addObject(rEncrypted);
										output.writeObject(response);
										continue;
									}
							}
						}
						catch(Exception e){
							System.out.println("Something failed when trying to delete group.");
							response = new Envelope("FAIL"); //something didn't work
							byte[] userNonceResponse = generateNonceResponse(userNonce);
							groupNonce = crypto.generateNonce(256);
							ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
								outputStream.write(userNonceResponse);
								outputStream.write(groupNonce);
							byte[] r = outputStream.toByteArray( );
							byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
							System.out.println("Sending back FAIL response.");
							response.addObject(rEncrypted);
							output.writeObject(response);
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
				}

				//-----------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
						System.out.println(user + " is trying to delete a group.");
						try{
							byte[] mEncrypted = (byte[])message.getObjContents().get(0);
							byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
							byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
							if(!verifyNonceResponse(groupNonceResponse)){
								System.out.println("User did not pass nonce response challenge");
							}
							else{	//user passed nonce response challenge
								userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
								byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
								int[] indexes = findNullIndex(subArray, 1);
								//extract components
								byte[] groupnameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]);//Extract the password
								String groupname = new String(groupnameBytes, StandardCharsets.UTF_8);
								byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[0]+1, subArray.length); //Extract the token
								Token token = (Token)crypto.deserializeToken(tokenBytes);
								System.out.println("Trying to delete group: " + groupname);
								//create group will return true or false depending on success of creating group
									if(deleteGroup(groupname, token))
									{
										response = new Envelope("OK"); //Success
										byte[] userNonceResponse = generateNonceResponse(userNonce);
										groupNonce = crypto.generateNonce(256);
										ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
											outputStream.write(userNonceResponse);
											outputStream.write(groupNonce);
										byte[] r = outputStream.toByteArray( );
										byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
										System.out.println("Sending back OK response.");
										response.addObject(rEncrypted);
										output.writeObject(response);
										continue;
									}
							}
						}
						catch(Exception e){
							System.out.println("Something failed when trying to delete group.");
							response = new Envelope("FAIL"); //something didn't work
							byte[] userNonceResponse = generateNonceResponse(userNonce);
							groupNonce = crypto.generateNonce(256);
							ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
								outputStream.write(userNonceResponse);
								outputStream.write(groupNonce);
							byte[] r = outputStream.toByteArray( );
							byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
							System.out.println("Sending back FAIL response.");
							response.addObject(rEncrypted);
							output.writeObject(response);
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
				}
				//--------------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
						System.out.println(user + " is trying to list members of a group.");
						try{
							byte[] mEncrypted = (byte[])message.getObjContents().get(0);
							byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
							byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
							if(!verifyNonceResponse(groupNonceResponse)){
								System.out.println("User did not pass nonce response challenge");
							}
							else{	//user passed nonce response challenge
								userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
								byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
								int[] indexes = findNullIndex(subArray, 1);
								//extract components
								byte[] groupnameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]);//Extract the password
								String groupname = new String(groupnameBytes, StandardCharsets.UTF_8);
								byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[0]+1, subArray.length); //Extract the token
								Token token = (Token)crypto.deserializeToken(tokenBytes);
								System.out.println("Trying to list members of group: " + groupname);
								//listmembers and serialize it
								List<String> memList = listMembers(groupname, token);
								ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
								ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
								objectOutput.writeObject(memList);
								byte[] memListBytes = byteOutput.toByteArray();
									if(memList != null)
									{
										response = new Envelope("OK"); //Success
										byte[] userNonceResponse = generateNonceResponse(userNonce);
										groupNonce = crypto.generateNonce(256);
										ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
											outputStream.write(userNonceResponse);
											outputStream.write(groupNonce);
											outputStream.write(memListBytes);
										byte[] r = outputStream.toByteArray( );
										byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
										System.out.println("Sending back OK response.");
										response.addObject(rEncrypted);
										output.writeObject(response);
										continue;
									}
							}
						}
						catch(Exception e){
							System.out.println("Something failed when trying to list members of group.");
							response = new Envelope("FAIL"); //something didn't work
							byte[] userNonceResponse = generateNonceResponse(userNonce);
							groupNonce = crypto.generateNonce(256);
							ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
								outputStream.write(userNonceResponse);
								outputStream.write(groupNonce);
							byte[] r = outputStream.toByteArray( );
							byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
							System.out.println("Sending back FAIL response.");
							response.addObject(rEncrypted);
							output.writeObject(response);
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
				}
				//-------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{
					System.out.println(user + " is trying to add a user to a group.");
					try{
						byte[] mEncrypted = (byte[])message.getObjContents().get(0);
						byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);

						byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
						if(!verifyNonceResponse(groupNonceResponse)){
							System.out.println("User did not pass nonce response challenge");
						}
						else{	//user passed nonce response challenge
							userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
							byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
							int[] indexes = findNullIndex(subArray, 2);
							//System.out.println("Null indexes at: " + indexes[0] + " and " + indexes[1]);
							byte[] usernameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]); //Extract the username
							String username = new String(usernameBytes, StandardCharsets.UTF_8);
							byte[] groupnameBytes = Arrays.copyOfRange(subArray, indexes[0]+1, indexes[1]);//Extract the password
							String groupname = new String(groupnameBytes, StandardCharsets.UTF_8);
							byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[1]+1, subArray.length); //Extract the token
							Token token = (Token)crypto.deserializeToken(tokenBytes);
						//	System.out.println("Token received: " + yourToken.toString());
							System.out.println("Trying to add user: " + username + " to group: " + groupname);
							if(addUserToGroup(username, groupname, token))
							{
								response = new Envelope("OK"); //Success
								byte[] userNonceResponse = generateNonceResponse(userNonce);
								groupNonce = crypto.generateNonce(256);
								ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
									outputStream.write(userNonceResponse);
									outputStream.write(groupNonce);
								byte[] r = outputStream.toByteArray( );
								byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
								System.out.println("Sending back OK response");
								response.addObject(rEncrypted);
								output.writeObject(response);
								continue;
							}
							else{
								System.out.println("User was not successfully added to group.");
							}
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}
					catch(Exception e){
						System.out.println("Something failed when trying to add user to group.");
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}

				}
				//-----------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					System.out.println(user + " is trying to remove a user from a group.");
					try{
						byte[] mEncrypted = (byte[])message.getObjContents().get(0);
						byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);

						byte[] groupNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
						if(!verifyNonceResponse(groupNonceResponse)){
							System.out.println("User did not pass nonce response challenge");
						}
						else{	//user passed nonce response challenge
							userNonce = Arrays.copyOfRange(mDecrypted, 32, 64);
							byte[] subArray = Arrays.copyOfRange(mDecrypted, 64, mDecrypted.length);
							int[] indexes = findNullIndex(subArray, 2);
							//System.out.println("Null indexes at: " + indexes[0] + " and " + indexes[1]);
							byte[] usernameBytes = Arrays.copyOfRange(subArray, 0, indexes[0]); //Extract the username
							String username = new String(usernameBytes, StandardCharsets.UTF_8);
							byte[] groupnameBytes = Arrays.copyOfRange(subArray, indexes[0]+1, indexes[1]);//Extract the password
							String groupname = new String(groupnameBytes, StandardCharsets.UTF_8);
							byte[] tokenBytes = Arrays.copyOfRange(subArray, indexes[1]+1, subArray.length); //Extract the token
							Token token = (Token)crypto.deserializeToken(tokenBytes);
						//	System.out.println("Token received: " + yourToken.toString());
							System.out.println("Trying to remove user: " + username + " from group: " + groupname);
							if(deleteUserFromGroup(username, groupname, token))
							{
								response = new Envelope("OK"); //Success
								byte[] userNonceResponse = generateNonceResponse(userNonce);
								groupNonce = crypto.generateNonce(256);
								ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
									outputStream.write(userNonceResponse);
									outputStream.write(groupNonce);
								byte[] r = outputStream.toByteArray( );
								byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
								System.out.println("Sending back OK response");
								response.addObject(rEncrypted);
								output.writeObject(response);
								continue;
							}
							else{
								System.out.println("User was not successfully deleted from group.");
							}
						}
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}
					catch(Exception e){
						System.out.println("Something failed when trying to remove user from group.");
						response = new Envelope("FAIL"); //something didn't work
						byte[] userNonceResponse = generateNonceResponse(userNonce);
						groupNonce = crypto.generateNonce(256);
						ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
							outputStream.write(userNonceResponse);
							outputStream.write(groupNonce);
						byte[] r = outputStream.toByteArray( );
						byte[] rEncrypted = crypto.aesEncrypt(r, sharedKey);
						System.out.println("Sending back FAIL response.");
						response.addObject(rEncrypted);
						output.writeObject(response);
					}

				}
				//------------------------------------------------------------------------------------------------
				else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}

				//shutdown??
				else if (message.getMessage().equals("DISCONNECT and SHUTDOWN")){
					//System.out.println("SHUTDOWN SERVER!!!!!!!!!!");

					socket.close(); //Close the socket
					proceed = false;
					System.exit(0);
				}

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
			yourToken.signToken(privateGSKey);
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

				GroupList copyList = my_gs.groupList.deepCopyList();
				UserList copyListU = my_gs.userList.deepCopyUserList();
				my_gs.groupList = copyList;
				my_gs.userList = copyListU;
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
					GroupList copyList = my_gs.groupList.deepCopyList();
					UserList copyListU = my_gs.userList.deepCopyUserList();
					my_gs.groupList = copyList;
					my_gs.userList = copyListU;
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
					GroupList copyList = my_gs.groupList.deepCopyList();
					my_gs.groupList = copyList;
					UserList copyListU = my_gs.userList.deepCopyUserList();
					my_gs.userList = copyListU;
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

	private boolean verifyNonceResponse(byte[] response){
		System.out.print("Testing to see if user's challenge response is accurate.");
		BigInteger groupNonceBigInt = new BigInteger(groupNonce);
		groupNonceBigInt = groupNonceBigInt.subtract(BigInteger.valueOf(1));
		BigInteger groupNonceResponse = new BigInteger(response);
		if(groupNonceBigInt.equals(groupNonceResponse)){
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

	private int[] findNullIndex(byte[] arr, int numIndexes){
		System.out.println("Finding null indices");
		int[] ret = new int[numIndexes];
		int i=0;
		int count = 0;
		while(i<numIndexes && count < arr.length){
			if(arr[count] == (byte)0x00){
				ret[i]=count;
				i++;
			}
			count++;
		}
		return ret;
	}

}
