import java.security.*;
import java.util.Hashtable;
import java.util.ArrayList;

class KeyDatabase implements java.io.Serializable{
  private static final long serialVersionUID = 6831008788225490740L;
  Hashtable<String,ArrayList<FileKeyPair>> data;
  private static Crypto crypto = new Crypto();

  public KeyDatabase(){
    data = new Hashtable<String,ArrayList<FileKeyPair>>();
  }
  //generates a new FileKeyPair item for a group
  public synchronized FileKeyPair newKey(String groupname){
    //check to see if group exists in the HashTable
    ArrayList<FileKeyPair> arr = new ArrayList<FileKeyPair>();
    if(data.containsKey(groupname)){
      arr = data.remove(groupname);   //get might be more save
    }
    //generate two new AES keys
    Key fileKey = crypto.generateAesKey(256);
    Key hashKey = crypto.generateAesKey(256);
    //reinitialize crypto for a new randomized IV (probably a better way to do this)
    crypto = new Crypto();
    byte[] iv = crypto.getIV();
    FileKeyPair keys = new FileKeyPair(fileKey, hashKey, iv, groupname);
    arr.add(keys);
    data.put(groupname, arr);
    return keys;
  }

  public ArrayList<FileKeyPair> getKeys(String groupname){
    return data.get(groupname);
  }
  public synchronized boolean deleteGroup(String groupname){
    if(data.remove(groupname)==null){
      return false;
    }
    else{
      return true;
    }
  }

}
