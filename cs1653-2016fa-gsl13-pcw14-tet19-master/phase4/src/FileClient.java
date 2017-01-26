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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.ByteBuffer;

public class FileClient extends Client implements FileClientInterface {

		private static Crypto crypto = new Crypto();
		private Key sharedKey;
		private byte[] userNonce;
		private byte[] fileNonce;
		private Key fsKey;
		private Key hmacKey;
		private int incomingCount = 0;
		private int outgoingCount = 0;
		private boolean authenticate2 = false;

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
			sharedKey = crypto.generateAesKey(256);
			hmacKey = crypto.generateAesKey(256);

			byte[] aesKeyBytes = sharedKey.getEncoded();
			byte[] iv = crypto.getIV();
			byte[] hmacKeyBytes = hmacKey.getEncoded();

			Envelope message = null, response = null;
			//put these together
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			try{
				outputStream.write(userNonce);
				outputStream.write(aesKeyBytes);
				outputStream.write(hmacKeyBytes);
				outputStream.write(iv);
			}
			catch(Exception e){
				System.out.println("Error with ByteArrayOutputStream");
				System.exit(0);
			}
			byte message1[] = outputStream.toByteArray( );
			byte[] message1Cipher = crypto.rsaEncrypt(message1, fsKey);

			//send to server
			System.out.println("\nSending message 1 to server.");
			message = new Envelope("AUTHENTICATE1");
			message.addObject(message1Cipher);

			// add hmac of encrypted message
			byte[] hmac = crypto.hmac(message1Cipher, hmacKey);
			message.addObject(hmac);

			output.writeObject(message);		//send it!

			// get a response from server
			Envelope wrapper = (Envelope)input.readObject();
			System.out.println("Received message 2 from server");

			// verify hmac
			byte[] ciphertextBytes = (byte[])wrapper.getObjContents().get(0);
			byte[] hmacBytes = (byte[])wrapper.getObjContents().get(1);
			if (!crypto.verifyHmac(hmacBytes, ciphertextBytes, hmacKey)) {
				System.out.println("Invalid HMAC! Message from File Server may have been tampered with.");
				System.out.println("Will close connection to server now.");
				this.disconnect();
			}
			System.out.println("Integrity of message verified with hmac.");

			byte[] envelopeBytes = crypto.aesDecrypt(ciphertextBytes, sharedKey);
			// turn inner envelope bytes back into envelope
      response = (Envelope)deserialize(envelopeBytes);

			if(response.getMessage().equals("OK")) {
				//Step 2 --------------------------------------------------------------------------------
				byte[] nonceResponse = (byte[])response.getObjContents().get(0);

				//test to see if the file server's challenge response is accurate
				if(verifyNonceResponse(nonceResponse)){
					authenticated = true;
					System.out.println("File Server authenticated");

					// only update fileNonce if file server authenticated
					fileNonce = (byte[])response.getObjContents().get(1);

					outputStream.reset();
				}
			}
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
		String[] params = {remotePath};

		/* Create inner envelope containing request, message counter, token, params,
		and nonce response if it has not been sent yet. Encrypt inner envelope and
		place in outer "wrapper" envelope */
		Envelope env = packageRequest("DELETEF", params, token);

    try {
			output.writeObject(env);

			Envelope wrapper = (Envelope)input.readObject();
			// extract and decrypt inner envelope and verify counter
			env = extractResponse(wrapper, output, input);

			if (env.getMessage().compareTo("OK")==0) {
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

	public boolean download(String sourceFile, String destFile, UserToken token, String groupname) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}

				File file = new File(destFile);
			    try {
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
							String[] params = new String[] {sourceFile};

							/* Create inner envelope containing request, message counter, token, params,
							and nonce response if it has not been sent yet. Encrypt inner envelope and
							place in outer "wrapper" envelope */
						  Envelope env = packageRequest("DOWNLOADF", params, token);

							output.writeObject(env);

							// extract and decrypt inner envelope and verify counter
							Envelope wrapper = (Envelope)input.readObject();
							env = extractResponse(wrapper, output, input);


							while (env.getMessage().compareTo("CHUNK")==0) {

								// write decrypted file chunk to buffer
								fos.write((byte[])env.getObjContents().get(1), 0, (Integer)env.getObjContents().get(2));
								System.out.printf(".");

								Envelope message = packageRequest("DOWNLOADF", null, token);
								output.writeObject(message);

								// get response
								wrapper = (Envelope)input.readObject();
								// extract and decrypt inner envelope and verify counter
								env = extractResponse(wrapper, output, input);
							}
							fos.close();

					    if(env.getMessage().compareTo("EOF") == 0) {
					    	fos.close();
								System.out.printf("\nTransfer successful of encrypted file %s\n", sourceFile);
								Envelope message = packageRequest("OK", null, token);
								output.writeObject(message);

								//T6: need to read in new file, decrypt and write out again
								Path path = Paths.get(destFile);
								byte[] data = Files.readAllBytes(path);
								byte[] versionBytes = Arrays.copyOfRange(data,0,4);
								byte[] hmacBytes = Arrays.copyOfRange(data,4,36);
								byte[] fileBytes = Arrays.copyOfRange(data,36,data.length);
								System.out.println("File Data is length: " + fileBytes.length);
								//get version number
								int version = java.nio.ByteBuffer.wrap(versionBytes).getInt();
								System.out.println("This file belongs to group: " + groupname);
								System.out.println("This file was encrypted using key version number: " + version);
								//Get the key from the right group
								ArrayList<FileKeyPair> keychain;
								if (ClientGUI.g_client.fileKeys != null)
									keychain= ClientGUI.g_client.fileKeys.get(groupname);
								else
									keychain = ClientApp.g_client.fileKeys.get(groupname);
								FileKeyPair kp = keychain.get(version);
								System.out.println("FileKeyPair being used for this file: " + kp.toString());
								System.out.println("HMAC for this file: " + Utils.formatByteArray(hmacBytes));
								System.out.println("Verifying HMAC: ");
								//TO-DO: FIX HMAC VERIFICATION
								if(crypto.verifyHmac(hmacBytes,fileBytes,kp.getHashKey())){
									System.out.println("\tHMAC was verified. File has not been tampered with.");
									//decrypt the file bytes
									Crypto crypto2 = new Crypto(kp.getIV());
									fileBytes = crypto2.aesDecrypt(fileBytes, kp.getFileKey());
									file.delete();
									FileOutputStream fos2 = new FileOutputStream(destFile);
									fos2.write(fileBytes);
									fos2.close();

									if(version < (keychain.size()-1)){
										System.out.println("Encryption of this file is out of date! Updating the file encryption.");
										kp = keychain.get(keychain.size()-1);			//get the keys
										//T6: REUPLOAD file
										//First send a request to delete
										if(delete(sourceFile, token)){
											System.out.println("Deleted old file on file server.");
											//Next, send upload with new file
											//Note: upload params
											//public boolean upload(String sourceFile, String destFile, String group, UserToken token, int versionNum, FileKeyPair fileKeyPair)
											boolean success = upload(destFile, sourceFile, groupname, token, keychain.size()-1, kp);
											//Note: destFile and sourceFile are flipped because upload and download have opposite sources and destinations
											if(success){
												System.out.println("Successfully updated file on server!");
											}
											else{
												System.out.println("Did not successfully update file on server.");
											}
										}
										else{
											System.out.println("Error deleting old file to replace on file server.");
										}
									}
								}
								else{	//HMAC failed -> file was tampered with
									System.out.println("\tHMAC FAILED, BAD FILE.");
									file.delete();
									return false;
								}

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


			    }
					catch(IndexOutOfBoundsException e1){
						System.out.println("File not formatted properly, not creating it.");
						file.delete();
						return false;
					}
					 catch (IOException e1) {

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

			 /* Create inner envelope containing request, message counter, token, params,
			 and nonce response if it has not been sent yet. Encrypt inner envelope and
			 place in outer "wrapper" envelope */
			 message = packageRequest("LFILES", null, token);
			 output.writeObject(message);

			 // get response from server
			 Envelope wrapper = (Envelope)input.readObject();
			 if (wrapper.getObjContents().size() == 0){
				 System.out.println(wrapper.getMessage());
				 return null;
			 }
			 e = extractResponse(wrapper, output, input);


			 //If server indicates success, return the file list
			 if(e.getMessage().equals("OK"))
			 {
				List<String> fileList = (List)e.getObjContents().get(1);
				return fileList;
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
			UserToken token, int versionNum, FileKeyPair fileKeyPair) {

		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }

		try {

			Envelope message = null, env = null;

			String[] params = new String[] {destFile, group};

			/* Create inner envelope containing request, message counter, token, params,
			and nonce response if it has not been sent yet. Encrypt inner envelope and
			place in outer "wrapper" envelope */
			message = packageRequest("UPLOADF", params, token);

			output.writeObject(message);

			//read entire file into byte array
			Path path = Paths.get(sourceFile);
			byte[] fileDataRaw = Files.readAllBytes(path);
			System.out.println("File Data is length: " + fileDataRaw.length);
			//make sure the IV is right
			Crypto crypto2 = new Crypto(fileKeyPair.getIV());
			//Encrypt it!
			fileDataRaw = crypto2.aesEncrypt(fileDataRaw,fileKeyPair.getFileKey());
			System.out.println("Encrypted File Data is length: " + fileDataRaw.length);
			//put it all together
			byte[] fileData = new byte[fileDataRaw.length + 36];
			byte[] version = ByteBuffer.allocate(4).putInt(versionNum).array();
			//need to HMAC the entire ENCRYPTED file
			byte[] hmac = crypto2.hmac(fileDataRaw, fileKeyPair.getHashKey());
			System.out.println("HMAC for this file: " + Utils.formatByteArray(hmac));
			for(int i=0; i<version.length;i++){
				fileData[i] = version[i];
			}
			for(int i=0; i<hmac.length;i++){
				fileData[i+version.length] = hmac[i];
			}
			for(int i=0; i<fileDataRaw.length;i++){
				fileData[i+version.length+hmac.length] = fileDataRaw[i];
			}
			System.out.println("New File with Version and HMAC length: " + fileData.length);

			FileInputStream fis = new FileInputStream(sourceFile);

			// response from server
			Envelope wrapper = (Envelope)input.readObject();
			env = extractResponse(wrapper, output, input);

			// Check to see if server is ready for upload
			if(env.getMessage().equals("READY")) {
				System.out.printf("Meta data upload successful\n");
			}
			else {
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			}

			boolean firstChunk = false;
			int fileDataIndex = 0;

			do {
				int n=0;
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY") != 0) {
					System.out.printf("Server error: %s\n", env.getMessage());
				 	return false;
			 	}
			 	message = new Envelope("CHUNK");
				//n = fis.read(buf); //can throw an IOException
				for(int i=0; i<buf.length && fileDataIndex<fileData.length ;i++){
					//System.out.println("file data index: " + fileDataIndex);
					buf[i] = fileData[fileDataIndex];
					fileDataIndex++;
					n++;
				}
				if (n > 0) {
					System.out.printf(".");
				}
				else if (n < 0) {
					System.out.println("Read error");
					return false;
				}
				System.out.println("Ended this not-first chunk at data index: " + fileDataIndex);


				message.addObject(buf);
				message.addObject(new Integer(n));  // length of buffer

				/* Create inner envelope containing message counter, buffer, and buffer size.
				Encrypt inner envelope and place in outer "wrapper" envelope */
				wrapper = packageRequest(message);
				output.writeObject(wrapper);

				// response
				wrapper = (Envelope)input.readObject();
				env = extractResponse(wrapper, output, input);

			}while(fileDataIndex < fileData.length);
			//while (fis.available()>0);
			System.out.println("Ended file data index at: " + fileDataIndex);

			if(env.getMessage().compareTo("READY") == 0) {

				message = new Envelope("EOF");
				wrapper = packageRequest(message);
				// send
				output.writeObject(wrapper);

				// response
				wrapper = (Envelope)input.readObject();
				env = extractResponse(wrapper, output, input);


				if(env.getMessage().compareTo("OK")==0) {
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}
			}
			else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
		}
		catch(Exception e1) {
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
		System.out.print("Testing to see if server's challenge response is accurate.");
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
			System.out.println("\nComputing response to server challenge");
			BigInteger responseBigInt = new BigInteger(original);		//computing R1-1
			responseBigInt = responseBigInt.subtract( BigInteger.valueOf(1) );
			byte[] nonceResponse = responseBigInt.toByteArray();
			return nonceResponse;
	}


	/* This methods packages message count, token, parameter together in a newly created
		inner envelope, and if it the file server nonce response has not been sent
		yet, it includes that as well. The inner envelope is encrypted and placed
		inside a "wrapper" envelope
		TODO: add HMAC
		*/
	private Envelope packageRequest(String message, String[] params, UserToken token) {

		Envelope e = new Envelope(message);
		e.addObject((Integer)outgoingCount);
		outgoingCount++;
		e.addObject(token);
		e.addObject(params);

		if (!authenticate2){
			byte[] fileNonceResponse = generateNonceResponse(fileNonce);
			e.addObject(fileNonceResponse);
			authenticate2 = true;
		}
		byte[] envBytes = serialize(e);
		byte[] cipher = crypto.aesEncrypt(envBytes, sharedKey);

		// generate hmac of encrypted envelope
		byte[] hmac = crypto.hmac(cipher, hmacKey);

		Envelope wrapper = new Envelope("AES");
		wrapper.addObject(cipher);
		wrapper.addObject(hmac);
		return wrapper;
	}

	/* This method takes an already formed envelope, encrypts it, and places
		it inside a wrapper envelope.
		 */

	private Envelope packageRequest(Envelope inner) {
		System.out.println("Sending Message #" + outgoingCount);
		inner.getObjContents().add(0, (Integer)outgoingCount);
		outgoingCount++;
		byte[] envBytes = serialize(inner);
		byte[] cipher = crypto.aesEncrypt(envBytes, sharedKey);
		// generate hmac of encrypted envelope
		byte[] hmac = crypto.hmac(cipher, hmacKey);

		// Add encrypted inner envelope and hmac to wrapper envelope
		Envelope wrapper = new Envelope("AES");
		wrapper.addObject(cipher);
		wrapper.addObject(hmac);
		return wrapper;
	}

	/* This method takes an envelope which contains an encrypted envelope inside of it.
		It decrypts the inner envelope and returns it */
	private Envelope extractResponse(Envelope wrapper, ObjectOutputStream output, ObjectInputStream input) {
		byte[] cipher = (byte[])wrapper.getObjContents().get(0);
		byte[] hmac = (byte[]) wrapper.getObjContents().get(1);

		// Check to see if HMAC is valid
		boolean valid = crypto.verifyHmac(hmac, cipher, hmacKey);
		if (!valid) {
			System.out.println("Invalid HMAC from server! Envelope contents may have been tampered with.");
			System.out.println("Will disconnect now.");
			this.disconnect();
			return null;
		}
		System.out.println("\nIntegrity of response verified with HMAC.\n");
		// HMAC valid so continue and decrypt inner envelope
		byte[] msg = crypto.aesDecrypt(cipher, sharedKey);
		Envelope env = (Envelope)deserialize(msg);

		// Check counter
		Integer messageCount = (Integer)env.getObjContents().get(0);
		System.out.println("Received Message #" + messageCount + ": " + env.getMessage());
		if (messageCount != (incomingCount)){
			Envelope response = new Envelope("FAIL-MESSAGE_ORDER");
			try{
				output.writeObject(response);
				output.close();
				input.close();
				this.disconnect();
			}
			catch (Exception ex) {				}
		}
		System.out.println("Message order verified.\n");
		incomingCount++;
		return env;
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
}
