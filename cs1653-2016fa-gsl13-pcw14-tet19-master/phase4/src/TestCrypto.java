import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.nio.charset.*;
import javax.crypto.spec.*;

public class TestCrypto{
	public static void main(String[] args){
		System.out.println("Testing Crypto methods");
		Crypto crypto = new Crypto();
		String s1 = "hello world!";
		byte[] b = s1.getBytes(StandardCharsets.UTF_8);						//convert to byte array
		//String s2 = new String(b, StandardCharsets.UTF_8);			//test to convert back
		//System.out.println(s1.equals(s2));


		//Testing generate nonce and salt method-----------------------------------------
		byte[] nonce = crypto.generateNonce(256);		//256 bit nonce
		//System.out.println("Nonce bytes:" + Arrays.toString(nonce));
		byte[] salt = crypto.generateSalt(256);					//256 bit salt

		//display outputs
		System.out.println("\nMISC TESTS -------------------------------------------");
		System.out.println("Nonce bytes: " + Arrays.toString(nonce) );
		System.out.println("Salt bytes: " + Arrays.toString(salt) + "\n");

		//Testing generate AESKey -------------------------------------------------------------
		Key aesKey = crypto.generateAesKey(128);		//256 bit aesKey
		byte[] encryptedAES = crypto.aesEncrypt(b, aesKey);
		byte[] decryptedAES = crypto.aesDecrypt(encryptedAES, aesKey);

		//Display outputs
		System.out.println("\nAES TESTS -----------------------------------------------");
		System.out.println("AES Key:" +Arrays.toString(aesKey.getEncoded()));
		System.out.println("Original: " + s1);
		String encryptedAESString = new String(encryptedAES, StandardCharsets.UTF_8);
		System.out.println("Encrypted: " + encryptedAESString);
		String decryptedAESString = new String(decryptedAES, StandardCharsets.UTF_8);
		System.out.println("Decrypted: " + decryptedAESString);


		//TESTING RSA STUFF ------------------------------------------------------------------
		//generate RSA keys
		KeyPair kp = crypto.generateRSAKeyPair(2048); //2048 RSA key pair
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		//ENCRYPT
		byte[] ciphertextBytes = crypto.rsaEncrypt(b, publicKey);
		//DECRYPT
		byte[] plaintextBytes = crypto.rsaDecrypt(ciphertextBytes, privateKey);

		//Dispaly outputs
		System.out.println("\nRSA TESTS -----------------------------------------------");
		System.out.println("Original: " + s1);
		String ciphertext = new String(ciphertextBytes, StandardCharsets.UTF_8);
		System.out.println("Encrypted: " + ciphertext);
		String plaintext = new String(plaintextBytes, StandardCharsets.UTF_8);
		System.out.println("Decrypted: " + plaintext);


		//Testing Mech 1, Step 1 ----------------------------------------------------------------
		System.out.println("\nTesting Mechanism 1: Step 1---------------------------------");
		String username = "terrytini";
		byte[] usernameBytes = username.getBytes(StandardCharsets.UTF_8);
		byte[] nonce1 = crypto.generateNonce(256);
		Key aesKey2 = crypto.generateAesKey(128);		//256 bit aesKey
		byte[] aesKeyBytes = aesKey2.getEncoded();
		System.out.println("LENGTHS:    username: " + usernameBytes.length + " || nonce: " + nonce1.length + " || aesKey: " + aesKeyBytes.length);
		//Put all the parts together to form: {username||R1||K_AG}
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try{
			outputStream.write( usernameBytes );
			outputStream.write( nonce1 );
			outputStream.write(aesKeyBytes);
		}
		catch(Exception e){
			System.out.println("Error with ByteArrayOutputStream");
			System.exit(0);
		}
		byte message1[] = outputStream.toByteArray( );
		//Encrypt it
		byte[] m1Encrypted = crypto.rsaEncrypt(message1, publicKey);
		//SEND IT ACROSS ->
		//Decrypt it
		byte[] m1Decrypted = crypto.rsaDecrypt(m1Encrypted, privateKey);
		//Extract all the parts
		byte[] usernameDecrypted = Arrays.copyOfRange(m1Decrypted, 0, m1Decrypted.length-48);
		String usernameDecryptedString = new String(usernameDecrypted, StandardCharsets.UTF_8);
		byte[] nonce1Decrypted = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length-48,m1Decrypted.length-16);
		byte[] keyDecrypted = Arrays.copyOfRange(m1Decrypted, m1Decrypted.length-16,m1Decrypted.length);
		//NOTE: for some reason, a 256-bit Key Object is encoded in only 16 bytes instead of 32 (idk why)

		//Test statements
		System.out.println("Username decrypted + extracted correctly: " + usernameDecryptedString.equals(username));
		System.out.println("Nonce 1 decrypted + extracted correctly: " + Arrays.equals(nonce1Decrypted, nonce1));
		System.out.println("Key decrypted + extracted correctly: " + Arrays.equals(keyDecrypted, aesKeyBytes));

		//End of Mech 1, Step 1 testing --------------------------------------------------------------------

		//Testing Mech 1, Step 2 ----------------------------------------------------------------------------
		System.out.println("\nTesting Mechanism 1: Step 2---------------------------------");
		//generate new challenge and response to the challenge
		byte[] nonce2 = crypto.generateNonce(256);
		BigInteger nonce1BigInt = new BigInteger(nonce1Decrypted);		//computing R1-1
		nonce1BigInt = nonce1BigInt.subtract( BigInteger.valueOf(1) );
		byte[] nonce1Response = nonce1BigInt.toByteArray();
		//put all parts together to form: {R1-1 || R2}
		ByteArrayOutputStream outputStream2 = new ByteArrayOutputStream( );
		try{
			outputStream2.write(nonce1Response);
			outputStream2.write(nonce2);
		}
		catch(Exception e){
			System.out.println("Error with ByteArrayOutputStream");
			System.exit(0);
		}
		byte message2[] = outputStream2.toByteArray( );
		//Encrypt it
		Key sharedKey = new SecretKeySpec(keyDecrypted, "AES");
		//Note: Key was converted into bytes before for transfer, need to re-encode
		byte[] m2Encrypted = crypto.aesEncrypt(message2, sharedKey);
		//SEND IT ACROSS <-
		//Decrypt it
		byte[] m2Decrypted = crypto.aesDecrypt(m2Encrypted, sharedKey);
		//Extract all the parts
		byte[] nonce1ResponseDecrypted = Arrays.copyOfRange(m2Decrypted, 0, 32);		//make sure response is checked in actual project
		byte[] nonce2Decrypted = Arrays.copyOfRange(m2Decrypted, 32, 64);

		//test statements
		System.out.println("Nonce1Response size: " + nonce1Response.length + " || Nonce2 size: " + nonce2.length);
		System.out.println("Respone R1-1 decrypted and extracted correctly: " + Arrays.equals(nonce1ResponseDecrypted, nonce1Response));
		System.out.println("Nonce 2 decrypted and extracted correctly: " + Arrays.equals(nonce2, nonce2Decrypted));

		//End of Mech 1, Step 2 testing --------------------------------------------------------------------

		//Testing Mech 1, Step 3 ----------------------------------------------------------------------------
		System.out.println("\nTesting Mechanism 1: Step 3---------------------------------");
		//generate response to challenge and password
		BigInteger nonce2BigInt = new BigInteger(nonce2Decrypted);
		nonce2BigInt = nonce2BigInt.subtract( BigInteger.valueOf(1) );
		byte[] nonce2Response = nonce2BigInt.toByteArray();
		String password = "CryptoIsAwesome!!";	//ask user for password in actual project
		byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
		//put all the parts together to form: {R2-1 || password}
		outputStream.reset();
		try{
			outputStream.write(nonce2Response);
			outputStream.write(passwordBytes);
		} catch( Exception e) {
			System.out.println("Error with bytearrayoutputstream.");
			System.exit(0);
		}
		byte[] message3 = outputStream.toByteArray();
		//Encrypt it
		byte[] m3Encrypted = crypto.aesEncrypt(message3, sharedKey);
		//Decrypt it
		byte[] m3Decrypted = crypto.aesDecrypt(m3Encrypted, sharedKey);
		//Extract all parts
		byte[] nonce2ResponseDecrypted = Arrays.copyOfRange(m3Decrypted,0,32);
		byte[] passwordBytesDecrypted = Arrays.copyOfRange(m3Decrypted,32,m3Decrypted.length);

		//In actual project, match h(salt || password ) against database o/

		//test statements
		System.out.println("Response R1-1 decrypted and extracted correctly: " + Arrays.equals(nonce2Response, nonce2ResponseDecrypted));
		System.out.println("Password was decrypted and extracted correctly: " + Arrays.equals(passwordBytes, passwordBytesDecrypted));

		//End of Mech 1, Step 3 testing --------------------------------------------------------------------
		//Testing Mech 1, Step 4 ----------------------------------------------------------------------------
		System.out.println("\nTesting Mechanism 1: Step 3---------------------------------");
		//Create the Token
		List<String> groups = new ArrayList<String>();
		groups.add("catloversz");
		groups.add("csc");
		groups.add("math club");
		Token myToken = new Token("Adam Lee", "Terry Tan", groups);
		byte[] tokenBytes = crypto.serializeToken(myToken);

		Token myToken2 = (Token)crypto.deserializeToken(tokenBytes);

		System.out.println(myToken.toString());
		System.out.println(myToken2.toString());
		//End of Mech 1, Step 4 testing --------------------------------------------------------------------


		// Testing signatures
		String toHash = "this is a string to hash";
		byte[] hashedString = crypto.hashSHA_256(toHash);
		byte[] signedString = crypto.signRSA(hashedString, privateKey);
		System.out.println("RSA Signature is valid: " + crypto.verifyRSASig(hashedString, signedString, publicKey));
		myToken.signToken(privateKey);
		byte[] signedToken = myToken.getSignature();
		String tokenStr = myToken.toString();
		byte[] tokenHash = crypto.hashSHA_256(tokenStr);

		System.out.println("Token signature verified: " + crypto.verifyRSASig(tokenHash,  signedToken, publicKey));


		// TESTING hmac

		Key secretKey = crypto.generateAesKey(128);

		String msgToHmac = "this is a string to HMAC";
		byte[] msgToHmacBytes = msgToHmac.getBytes();
		byte[] encryptedMsgToHmac = crypto.aesEncrypt(msgToHmacBytes, secretKey);

		Key hmacKey = crypto.generateAesKey(128);
		byte[] msgHmacBytes = crypto.hmac(encryptedMsgToHmac, hmacKey);

		System.out.println("HMAC verified " + crypto.verifyHmac(msgHmacBytes, encryptedMsgToHmac, hmacKey));
		System.out.println("HMAC verified when use wrong key " + crypto.verifyHmac(msgHmacBytes, encryptedMsgToHmac, secretKey));






	}
}
