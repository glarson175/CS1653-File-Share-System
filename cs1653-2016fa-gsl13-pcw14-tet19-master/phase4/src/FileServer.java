/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.nio.charset.*;
import java.util.Scanner;
import java.util.Base64;
import java.util.Arrays;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;

	public Key publicKey;     // The public key of this server
  public Key privateKey;    // The private key of this server
	private PublicKey gsKey;  // public key of GroupServer--should be pre-loaded as config file
	Crypto crypto = new Crypto();

	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}

	public Key getFSpublicKey()
	{
		return publicKey;
	}

	public Key getFSprivateKey(){
		return privateKey;
	}

	public PublicKey getGSKey() {
		return gsKey;
	}

	public void start() {

		boolean hasGSKey = readGroupServerKey();
		if (!hasGSKey) {
			System.out.println("File Server unable to be run without a saved GroupServer public key");
			System.exit(-1);
		}

		String fileFile = "FileList.bin";
		String keyFile = "FileKeyPair.bin";
		ObjectInputStream fileStream = null;
		ObjectInputStream keyStream = null;
		FileInputStream fis = null;
		KeyPair keyPair; // the keypair

		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		//Open user file to get user list
		try
		{
			fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();

			//open and read FileList.bin
			fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();

			// read FileKeyPair.bin
			fis = new FileInputStream(keyFile);
			keyStream = new ObjectInputStream(fis);
			keyPair = (KeyPair)keyStream.readObject();
			publicKey = keyPair.getPublic();
			privateKey = keyPair.getPrivate();

			System.out.println("Public key(full): " + Utils.formatByteArray(publicKey.getEncoded()));
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

			System.out.println("Creating new KeyPair...");
			try
			{
				keyPair = crypto.generateRSAKeyPair(2048);
				publicKey  = keyPair.getPublic();
				privateKey = keyPair.getPrivate();
				ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(keyFile));
				outputStream.writeObject(keyPair);
				outputStream.close();

				String keyString = new String(crypto.hashSHA_256(Base64.getEncoder().encodeToString(publicKey.getEncoded())), StandardCharsets.UTF_8);
				System.out.println("Public key (hash): " + keyString);
				System.out.println("Public key (full): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
			}
			catch ( IOException e1)
			{
					e1.printStackTrace();
			}
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			e.printStackTrace();
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
		}

		// Ensure streams are closed
		finally {
			try {
				if (fis != null) fis.close();
			} catch (IOException e){}
			try {
				if (fileStream != null) fileStream.close();
			} catch (IOException e){}
		}

		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");
		 }

		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();


		boolean running = true;
		Scanner keyboard = new Scanner(System.in);

			try
			{
				final ServerSocket serverSock = new ServerSocket(port);
				System.out.printf("%s up and running\n", this.getClass().getName());

				Socket sock = null;
				Thread thread = null;

				/*while (!(keyboard.next().equals("q")))
				{
						while(true && !(keyboard.hasNext()))
						{
							sock = serverSock.accept();
							thread = new FileThread(sock, this);
							thread.start();
						}
				}*/
				while(running)
				{
					sock = serverSock.accept();
					thread = new FileThread(sock, this);
					thread.start();
				}

				System.out.printf("%s shut down\n", this.getClass().getName());
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
	}

	private boolean readGroupServerKey() {
		boolean success = false;
		String keyFile = "GSPublicKey.config";
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(keyFile);
			ois = new ObjectInputStream(fis);
			gsKey = (PublicKey) ois.readObject();
			success = true;
		}
		catch (Exception e) {
			System.out.println("Problem reading GSPublicKey.config");
			System.out.println("Group server public key must be added to home directory before using FileServer");
		}
		finally {
			if (fis != null){
				try { fis.close();}
				catch (IOException e){}
			}
			if (ois != null) {
				try {ois.close();}
				catch (IOException e){}
			}
		}
		return success;
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("\nShutting down server");
		System.out.println("\nGoodBye :) Have a Nice Day!!!\n");
		ObjectOutputStream outStream = null;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			// System.out.println(FileServer.fileList.toString());
			outStream.writeObject(FileServer.fileList);
			System.out.println("Successfully wrote to filelist.bin");

		}
		catch(Exception e)
		{
			System.out.println("Error: " + e.getMessage());
			e.printStackTrace();
		}
		finally {
			try {
				if (outStream != null) outStream.close();
			} catch(IOException e){}
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream = null;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
					System.out.println("Autosaved FileList.bin");
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				finally {
					try {
						if (outStream != null) outStream.close();
					} catch(IOException e){}
				}


			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}



}
