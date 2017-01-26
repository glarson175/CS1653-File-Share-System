import java.io.*;
import java.util.*;

public class TestDatabase{
	public static void main(String[] args){
		Database db = new Database();
		Crypto crypto = new Crypto();
		
		if(args.length == 0){
			//username: pauline || password: partyparrot
			String user1 = "pauline";
			String pass1 = "partyparrot";
			if(db.addItem(user1,pass1)){
				System.out.println("Successfully added " + user1);
			}
			else{
				System.out.println("Unsuccessful add.");
			}
			
			//username: terry || password: partycat
			String user2 = "terry";
			String pass2 = "partycat";
			if(db.addItem(user2, pass2)){
				System.out.println("Successfully added " + user2);
			}
			else{
				System.out.println("Unsuccessful add.");
			}
			
			//username: gabe || password: partypool
			String user3 = "gabe";
			String pass3 = "partypool";
			if(db.addItem(user3, pass3)){
				System.out.println("Successfully added " + user3);
			}
			else{
				System.out.println("Unsuccessful add.");
			}
			//--------------------------------------------------------------
			do{
				System.out.println("\nTry to log in as someone! (type q to quit)");
				Scanner in = new Scanner(System.in);
				System.out.print("Username: ");
				String username = in.next();
					if(username.equals("q")) break;
				System.out.print("Password: ");
				String password = in.next();
					if(password.equals("q")) break;
				if(db.checkItemExists(username)){
					if(db.checkItem(username, password)){
						System.out.println("Successful validation!");
					}
					else{
						System.out.println("Unsuccessful validation!");
					}
				}
				else{
					System.out.println("User does not exist!");
				}
			}while(true);
			//----------------------------------------------------------------------------------------
			System.out.println("Writing out to file!");
			ObjectOutputStream outStream = null;
			try{
				outStream = new ObjectOutputStream(new FileOutputStream("Database.bin"));
				outStream.writeObject( db);
				System.out.println("Successfully saved Database.bin");
			}
			catch(Exception e){
				System.out.println("Something went wrong.");
			}
			finally{
				 try {
							if (outStream != null) outStream.close();
				} catch(IOException e){}
			}
		}
		//-----------------------------------------------------------------------------------------
		System.out.println("Reading in from file!");
		Database new_db = new Database();
		String dbFile = "Database.bin";
		ObjectInputStream dbStream = null;
		FileInputStream dis = null;
		try{
			dis = new FileInputStream(dbFile);
			dbStream = new ObjectInputStream(dis);
			new_db = (Database)dbStream.readObject();
		}
		catch(Exception e){
			System.out.println("Error reading file: " + e.toString());
		}
		finally{
			try {
        if (dbStream != null) dbStream.close();
      } catch(IOException e){}
			try {
        if (dis != null) dis.close();
      } catch(IOException e){}
		}
		//-----------------------------------------------------------------------------------------
		//Test to see if we read things right
			do{
			System.out.println("\nTry to log in as someone! (type q to quit)");
			Scanner in = new Scanner(System.in);
			System.out.print("Username: ");
			String username = in.next();
				if(username.equals("q")) break;
			System.out.print("Password: ");
			String password = in.next();
				if(password.equals("q")) break;
			if(new_db.checkItemExists(username)){
				if(new_db.checkItem(username, password)){
					System.out.println("Successful validation!");
				}
				else{
					System.out.println("Unsuccessful validation!");
				}
			}
			else{
				System.out.println("User does not exist!");
			}
		}while(true);
	}
}