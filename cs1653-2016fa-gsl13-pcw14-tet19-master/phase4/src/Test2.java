import java.security.*;
import java.util.Hashtable;
import java.util.ArrayList;

class Test2{
  public static void main(String args[]){
    Crypto crypto = new Crypto();
    KeyDatabase db = new KeyDatabase();
    System.out.println("Hello world!");
    if(db.getKeys("hello") == null){
      System.out.println("Check point 1: Trying to get keys of nonexistent group - PASS ");
    }
    else{
      System.out.println("Check point 1: Trying to get keys of nonexistent group - FAIL ");
    }

    FileKeyPair fkp = db.newKey("everyone");
    System.out.println("Check point 2: Making a new key for a group\n" + fkp.toString());

    db.newKey("everyone");
    db.newKey("everyone");
    FileKeyPair testKeyPair = db.newKey("everyone");
    db.newKey("everyone");
    db.newKey("everyone");
    db.newKey("cats");
    db.newKey("cats");
    db.newKey("cats");
    db.newKey("cats");
    db.newKey("dogs");
    FileKeyPair testKeyPair2 = db.newKey("dogs");

    System.out.println("Check point 3: Making a bunch of keys for a group");
    ArrayList<FileKeyPair> everyoneKeys = db.getKeys("everyone");
    System.out.println("\tNumber Keys in everyone: " + everyoneKeys.size());
    ArrayList<FileKeyPair> catsKeys = db.getKeys("cats");
    System.out.println("\tNumber Keys in cats    : " + catsKeys.size());
    ArrayList<FileKeyPair> dogsKeys = db.getKeys("dogs");
    System.out.println("\tNumber Keys in dogs    : " + dogsKeys.size());

    System.out.println("Check point 4: Comparing version 3 of everyone.");
    //System.out.println("\t" + testKeyPair.toString());
    //System.out.println("\t" + everyoneKeys.get(3).toString());
    System.out.println("\t" + testKeyPair.toString().equals(everyoneKeys.get(3).toString()));

    //GET LATEST VERSION FROM ARRAYLIST
    FileKeyPair mostRecentDogs = dogsKeys.get(dogsKeys.size()-1);

    System.out.println("Check point 5: Comparing most recent version of dogs.");
    System.out.println("\t" + testKeyPair2.toString().equals(dogsKeys.get(1).toString()));

  }
}
