/* FileClient provides all the client functionality regarding the file server */
import java.io.*;
import java.io.File;
import java.security.*;
import java.util.*;
import java.io.*;
import java.nio.charset.*;
import java.math.*;
import javax.crypto.spec.*;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;


public class FileClient extends Client implements FileClientInterface {

		private static Crypto crypto = new Crypto();
		private Key sharedKey;
		private byte[] userNonce;
		private byte[] fileNonce;
		private Key fsKey;
		private final static byte[] ETX = new byte[]{(byte)0x03};

	public Key getFSKey(){

			try{
				Key key = null;
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
						key = (Key)temp.get(0);
						//System.out.println("From group client: Succesfully received group server's key!");
						fsKey = key;
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

	public boolean authenticate() throws IOException{

		boolean authenticated = false;
		try
		{

			userNonce = crypto.generateNonce(256);
			sharedKey = crypto.generateAesKey(128);
			byte[] aesKeyBytes = sharedKey.getEncoded();
			byte[] iv = crypto.getIV();
			Envelope message = null, response = null;
			//put these together
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			try{
				outputStream.write(userNonce);
				outputStream.write(aesKeyBytes);
				outputStream.write(iv);
			}
			catch(Exception e){
				System.out.println("Error with ByteArrayOutputStream");
				System.exit(0);
			}
			byte message1[] = outputStream.toByteArray( );

			byte[] m1Encrypted = crypto.rsaEncrypt(message1, fsKey); //encrypt with the servers public key


			//send to server

			System.out.println("Sending message 1 to server.");
			message = new Envelope("AUTHENTICATE1");
			message.addObject(m1Encrypted); //Add encrypted message
			output.writeObject(message);		//send it!

			// get a response from server
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

				//test to see if the file server's challenge response is accurate
				if(verifyNonceResponse(userNonceResponseDecrypted)){
					authenticated = true;
					System.out.println("File Server authenticated");
					fileNonce = Arrays.copyOfRange(m2Decrypted, 32, 64);
					// only update fileNonce if file server authenticated
					outputStream.reset();
				}
			}			//send it!
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			System.out.println("Something went wrong during authentication. Disconnect and try again.");
		}
		return authenticated;
	}

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
		String[] params = {remotePath};

		// pack nonces, params, and tokens together and encrypt in envelope
		env = packageRequest("DELETEF", params, token);

    try {
			output.writeObject(env);
	    env = (Envelope)input.readObject();
			// no contents, nothing to decrypt-- only success or fail

			if (env.getMessage().compareTo("OK")==0) {

				byte[] m2Encrypted = (byte[])env.getObjContents().get(0);

				//Decrypt it
				byte[] m2Decrypted = crypto.aesDecrypt(m2Encrypted, sharedKey);

				//Extract all the parts
				byte[] userNonceResponseDecrypted = Arrays.copyOfRange(m2Decrypted, 0, 32);

				//test to see if the file server's challenge response is accurate
				if(verifyNonceResponse(userNonceResponseDecrypted)){
					fileNonce = Arrays.copyOfRange(m2Decrypted, 32, 64);
				}
					// only update fileNonce if file server authenticated
				System.out.printf("File %s deleted successfully\n", filename);

			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
			    try {
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
							String[] params = new String[] {sourceFile};

							// Concat and encrypt params and token and nonces and add to envelope
							Envelope env = packageRequest("DOWNLOADF", params, token);
					    output.writeObject(env);

							// get response
					    env = (Envelope)input.readObject();

						while (env.getMessage().compareTo("CHUNK")==0) {
							// decrypt message in envelope
							byte[] decryptedBuf = decryptMessage(env);
							// write decrypted file chunk to buffer
							fos.write(decryptedBuf, 0, (Integer)env.getObjContents().get(1));
							System.out.printf(".");
							env = new Envelope("DOWNLOADF"); //Success
							output.writeObject(env);
							env = (Envelope)input.readObject();
						}
						fos.close();

					    if(env.getMessage().compareTo("EOF")==0) {
					    	fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								output.writeObject(env);
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;
						}
				    }

				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }


			    } catch (IOException e1) {

			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;

			 //package the request with appropriate nonces and token - params is null for this request
			 message = packageRequest("LFILES", null, token);
			 output.writeObject(message);

			 // get response from server
			 e = (Envelope)input.readObject();

			 //If server indicates success, return the file list
			 if(e.getMessage().equals("OK"))
			 {

				byte[] mEncrypted = (byte[])e.getObjContents().get(0);

				// decrypt message contents
				byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);

				// Extract new nonce challenge from server and update global if only verified
				// also extract file list
				List<String> fileList = extractResponseList(mDecrypted, 0);
				return fileList;
			 }

			 // error getting files - still need to check nonces

			 byte[] mEncrypted = (byte[])e.getObjContents().get(0);
			 // decrypt message contents
			 byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
			 byte[] fileNonceResponse = Arrays.copyOfRange(mDecrypted, 0, 32);
			 if (verifyNonceResponse(fileNonceResponse)) {
				 fileNonce = Arrays.copyOfRange(mDecrypted, 32, 32);
			 }
			 else {
				 System.out.println("Invalid nonce from file server");
			 }


			 return null;

		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}


	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try
		 {

			 Envelope message = null, env = null;

			 String[] params = new String[] {destFile, group};

			 // package request with nonces, params, and token and encrypt
			 message = packageRequest("UPLOADF", params, token);
			 //Ask the server to accept the file
			 output.writeObject(message);

			 FileInputStream fis = new FileInputStream(sourceFile);

			 // response from server
			 env = (Envelope)input.readObject();

			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 {
					System.out.printf("Meta data upload successful\n");
					byte[] mEncrypted = (byte[])env.getObjContents().get(0);
					// decrypt message contents
					byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
					boolean verified = extractResponseNonces(mDecrypted);
					if (!verified)
						return false;
			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 byte[] mEncrypted = (byte[])env.getObjContents().get(0);
				 // decrypt message contents
				 byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
				 boolean verified = extractResponseNonces(mDecrypted);
				 if (!verified)
					 return false;
				 return false;
			 }


			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}

					// encrypt buffer before adding to envelope
					byte[] encryptedBuf = crypto.aesEncrypt(buf, sharedKey);
					message.addObject(encryptedBuf);
					// length of buffer
					message.addObject(new Integer(n));

					output.writeObject(message);


					env = (Envelope)input.readObject();


			 }
			 while (fis.available()>0);

			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 {
				 byte[] mEncrypted = (byte[])env.getObjContents().get(0);
				 // decrypt message contents
				 byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
				 boolean verified = extractResponseNonces(mDecrypted);
				 if (!verified)
					 return false;

				message = new Envelope("EOF");
				output.writeObject(message);

				env = (Envelope)input.readObject();
				if(env.getMessage().compareTo("OK")==0) {
					mEncrypted = (byte[])env.getObjContents().get(0);
					// decrypt message contents
					mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
					verified = extractResponseNonces(mDecrypted);
					if (!verified)
						return false;
					System.out.printf("\nFile data upload successful\n");
				}
				else {

					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 mEncrypted = (byte[])env.getObjContents().get(0);
					 // decrypt message contents
					 mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
					 verified = extractResponseNonces(mDecrypted);
					 if (!verified)
						 return false;
					 return false;
				 }

			}
			 else {

				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 byte[] mEncrypted = (byte[])env.getObjContents().get(0);
				 // decrypt message contents
				 byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
				 boolean verified = extractResponseNonces(mDecrypted);
				 if (!verified)
					 return false;

				 return false;
			 }

		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}
	//HELPER METHODS -------------------------------------------------------------

	public void shutdown()
	{
			try
			{
				Envelope message = null;
				System.out.println("Sending Shutdown message to File Server.");
				message = new Envelope("DISCONNECT and SHUTDOWN");
				message.addObject(""); //Add null message
				output.writeObject(message);
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
	}

	 private boolean verifyNonceResponse(byte[] response){
		System.out.print("Testing to see if file server's challenge response is accurate.");
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


	/* This methods pacakges the nonces, parameters and token together in an encrypted byte array
	   which is added to an Envelope and returned. It also update the userNonce global to be a new nonce */
	private Envelope packageRequest(String message, String[] params, UserToken token) {
		// System.out.println("Token sig before packing " + Arrays.toString(token.getSignature()));
		Envelope e = new Envelope(message);
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

		int paramLength = 0;
		byte[] tokenBytes = crypto.serializeToken((Token)token);
		byte[] fileNonceResponse = generateNonceResponse(fileNonce);
		userNonce = crypto.generateNonce(256);
		try {
			outputStream.write(fileNonceResponse);
			outputStream.write(userNonce);
			if (params != null) {
				byte[] paramBytes = serialize(params);
				paramLength = paramBytes.length;
				outputStream.write(paramBytes);
				// System.out.println("params length " + paramBytes.length);
			}
			outputStream.write(tokenBytes);
			// System.out.println("token length " + tokenBytes.length);
		}
		catch (Exception ex) {
			System.out.println("problem packaging request");
			return null;
		}
		byte[] packagedRequest = outputStream.toByteArray();
		byte[] encryptedRequest = crypto.aesEncrypt(packagedRequest, sharedKey);
		e.addObject(encryptedRequest);
		e.addObject(paramLength);
		return e;
	}

	/// Extract file list from response
	@SuppressWarnings("unchecked")
	private  List<String> extractResponseList(byte[] message, int paramLength) {
		System.out.println("Message length " + message.length);
		byte[] nonceResponse = Arrays.copyOfRange(message, 0, 32);
		boolean trusted = verifyNonceResponse(nonceResponse);
		List<String> fileList = null;
		if (trusted){
			fileNonce = Arrays.copyOfRange(message, 32, 64);
			byte[] subArray = Arrays.copyOfRange(message, 64, message.length);
			byte[] listBytes = Arrays.copyOfRange(subArray, 0, subArray.length);
			fileList = (List<String>)deserialize(listBytes);
		}
		else {
			System.out.println("WARNING: file server failed nonce challenge");
		}
		return fileList;
	}


	private  boolean extractResponseNonces(byte[] message) {
		byte[] nonceResponse = Arrays.copyOfRange(message, 0, 32);
		boolean trusted = verifyNonceResponse(nonceResponse);
		if (trusted){
			fileNonce = Arrays.copyOfRange(message, 32, 64);
			return true;
		}
		else {
			System.out.println("WARNING: file server failed nonce challenge");
			return false;
		}
	}


	public static Object deserialize(byte[] bytes){
		try{
			ByteArrayInputStream byteInput = new ByteArrayInputStream(bytes);
			ObjectInputStream objectInput = new ObjectInputStream(byteInput);
			return objectInput.readObject();
		}
		catch(Exception e){
			System.out.println("Problem deserializing byte array!");
			return null;
		}
	}

	public static byte[] serialize(Object o){
		try{
			ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
			ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
			objectOutput.writeObject(o);
			return byteOutput.toByteArray();
		}
		catch(Exception e){
			System.out.println("Problem serializing object!");
			return null;
		}
	}

	public byte[] decryptMessage(Envelope message) {
			byte[] mEncrypted = (byte[])message.getObjContents().get(0);
			byte[] mDecrypted = crypto.aesDecrypt(mEncrypted, sharedKey);
			return mDecrypted;

	}



}
