
import java.util.*;
import java.security.*;


	public class KeyList implements java.io.Serializable {

	/*Serializable so it can be stored in a file for persistence */
	private static final long serialVersionUID = -8911161283900260136L;
	private Hashtable<String, Key> list = new Hashtable<String, Key>();

	public KeyList()
	{
	}

	public KeyList(Hashtable<String, Key> list) {
		this.list = list;
	}

	public void addKey(String address, int port, Key key)
	{
		String fullAddress = address + ":" + port;
		list.put(fullAddress, key);
		// System.out.println("Added key for " + fullAddress + " key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
	}

  public  boolean isTrustedKey(String address, int port, Key key) {
    String fullAddress = address + ":" + port;
    Key k = list.get(fullAddress);
    if (k!= null && k.equals(key))
      return true;
    return false;
  }

	public  boolean isEmpty(){
		return list.isEmpty();
	}

	public String toString(){
		StringBuilder s = new StringBuilder();
		for (String address : list.keySet()){
			s.append ("Address: " + address + "; Key: ");
			Key k = list.get(address);
			s.append(Base64.getEncoder().encodeToString(k.getEncoded()));
		}
		return s.toString();
	}




}
