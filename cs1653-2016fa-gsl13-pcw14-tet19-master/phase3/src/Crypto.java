import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.util.*;
import java.math.*;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Crypto{
		private Cipher rsaCipher;
		private Cipher aesCipher;
		private IvParameterSpec iv;

		public Crypto(){
			try{
				Security.addProvider(new BouncyCastleProvider());
				//Create RSA Cipher
				rsaCipher = Cipher.getInstance("RSA", "BC");
				//Create Aes cipher
				aesCipher = Cipher.getInstance("AES/CTR/PKCS5PADDING", "BC");
				//initialize Cipher
				iv = generateRandomIV(aesCipher);
			}
			catch(Exception e){
				System.out.println("Failed to create cipher.");
			}
		}
		public Crypto(byte[] ivbytes){
			try{
				Security.addProvider(new BouncyCastleProvider());
			//Create RSA Cipher
				rsaCipher = Cipher.getInstance("RSA", "BC");
				//Create Aes cipher
				aesCipher = Cipher.getInstance("AES/CTR/PKCS5PADDING", "BC");
				//initialize Cipher
				this.iv = generateIV(aesCipher, ivbytes);
			}
			catch(Exception e){
				System.out.println("Failed to create cipher.");
			}
		}

		//Method that generates a random nonce of size  numbits
		public byte[] generateNonce(int numBits){
			int numBytes = numBits/8;
			SecureRandom rand = new SecureRandom();
			byte[] vals = new byte[numBytes];
			rand.nextBytes(vals);
			return vals;
		}
		//Method that generates random salt of size numBits
		public byte[] generateSalt(int numBits){
			return generateNonce(numBits);
		}

		//Method that generates an AES key of size keySize bits
		public Key generateAesKey(int keySize){
			try{
				KeyGenerator kg = KeyGenerator.getInstance("AES");
				SecureRandom rand = new SecureRandom();
				kg.init(keySize, rand);
				Key key = kg.generateKey();
				return key;
			}
			catch(Exception e){
				System.out.println("Error: " + e.toString());
				return null;
			}
		}
		//generates RSA private/public key pair
		public KeyPair generateRSAKeyPair(int numBits){
			try{
				KeyPairGenerator rsaKeyGen;
				rsaKeyGen = KeyPairGenerator.getInstance("RSA");
				SecureRandom rand = new SecureRandom();
				rsaKeyGen.initialize(numBits);
				KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();
				return rsaKeyPair;

			}
			catch(Exception e){
				System.out.println("Error: " + e.toString());
				return null;
			}
		}
		//encryptes given bytes using RSA
		public byte[] rsaEncrypt(byte[] plaintextBytes, Key publicKey){
			try{
				rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
				byte[] ciphertextBytes = rsaCipher.doFinal(plaintextBytes);
				return ciphertextBytes;
			}
			catch(Exception e){
				System.out.println("Error 1: " + e.toString());
				return null;
			}

		}
		//decrypts given bytes using RSA
		public byte[] rsaDecrypt(byte[] ciphertextBytes, Key privateKey){
			try{
				rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
				byte[] plaintextBytes = rsaCipher.doFinal(ciphertextBytes);
				return plaintextBytes;
			}
			catch(Exception e){
				System.out.println("Error 2: " + e.toString());
				return null;
			}
		}

		public static byte[] signRSA(byte[] plainText, PrivateKey privateKey)  {
			// byte[] plainText = s.getBytes();
			// TODO:  change to BC signature?
			try {
				Signature signature = Signature.getInstance("SHA256withRSA");
				// generate a signature
				signature.initSign(privateKey);
				signature.update(plainText);
				byte[] sigBytes = signature.sign();
				return sigBytes;
			}
			catch (Exception e) {
				System.out.println("Error: " + e.toString());
				return null;
			}
		}

		public static boolean verifyRSASig(byte[] plainText, byte[] sigBytes, PublicKey publicKey)  {
			// byte[] plainText = s.getBytes();
			try{

				Signature signature = Signature.getInstance("SHA256withRSA");
				signature.initVerify(publicKey);
				signature.update(plainText);
				return signature.verify(sigBytes);
			}
			catch (Exception e) {
				System.out.println("Error: " + e.toString());
				return false;
			}
		}

		public byte[] hashSHA_256(String s){
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(s.getBytes("UTF-8"));
				byte[] digest = md.digest();
				return digest;
			}
			catch (Exception e) {
				System.out.println("Error: " + e.toString());
				return null;
			}
		}

		//encrypts bytes using AES
		public byte[] aesEncrypt(byte[] plaintextBytes, Key aesKey){
			try{
				//System.out.println("Crypto: Encrypting using this IV: " + Arrays.toString(iv.getIV()));
				aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
				byte[] ciphertextBytes = aesCipher.doFinal(plaintextBytes);
				return ciphertextBytes;
			}
			catch(Exception e){
				System.out.println("Error 3: " + e.toString());
				return null;
			}
		}
		//decrypts bytes using AES
		public byte[] aesDecrypt(byte[] ciphertextBytes, Key aesKey){
			try{
				//System.out.println("Crypto: Decrypting using this IV: " + Arrays.toString(iv.getIV()));
				aesCipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
				byte[] plaintextBytes = aesCipher.doFinal(ciphertextBytes);
			//	byte[] plaintextBytes = aesCipher.update(ciphertextBytes);
				return plaintextBytes;
			}
			catch(Exception e){
				System.out.println("Error 4: " + e.toString());
				return null;
			}
		}
		//priavte method for generating an IVP Spec
		private static IvParameterSpec generateRandomIV(Cipher cipher){
		try{
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			byte[] iv_bytes = new byte[cipher.getBlockSize()];
			random.nextBytes(iv_bytes);
			IvParameterSpec iv = new IvParameterSpec(iv_bytes);
			return iv;
		}
		catch(Exception e){
			System.out.println("Error: " + e.toString());
			return null;
		}
	}
		private static IvParameterSpec generateIV(Cipher cipher, byte[] ivbytes){
			IvParameterSpec iv = new IvParameterSpec(ivbytes);
			return iv;
		}
		public byte[] getIV(){
			return iv.getIV();
		}

	//writing token out as a byte array so it can be encrypted
	public byte[] serializeToken(Token token){
		try{
			ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
			ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
			objectOutput.writeObject(token);
			return byteOutput.toByteArray();
		}
		catch(Exception e){
			System.out.println("Problem serializing token!");
			return null;
		}
	}
	public Object deserializeToken(byte[] bytes){
		try{
			ByteArrayInputStream byteInput = new ByteArrayInputStream(bytes);
			ObjectInputStream objectInput = new ObjectInputStream(byteInput);
			return objectInput.readObject();
		}
		catch(Exception e){
			System.out.println("Problem deserializing token!");
			return null;
		}
	}
}
