import java.security.*;
import java.util.*;

class FileKeyPair implements java.io.Serializable{
  private static final long serialVersionUID = 8341345283112883958L;
  private Key fileKey;
  private Key hashKey;
  private byte[] iv;
  private String groupname;

  public FileKeyPair(Key f, Key h, byte[] i, String g){
    this.fileKey = f;
    this.hashKey = h;
    this.iv = i;
    this.groupname = g;
  }
  public String getGroupName(){
    return groupname;
  }
  public Key getFileKey(){
    return fileKey;
  }
  public Key getHashKey(){
    return hashKey;
  }
  public byte[] getIV(){
    return iv;
  }
  // public String toString(){
  //   String s1 = Base64.getEncoder().encodeToString(fileKey.getEncoded());
  //   String s2 = Base64.getEncoder().encodeToString(hashKey.getEncoded());
  //   String ivString = Arrays.toString(iv);
  //   return groupname + " " + ivString + " " + s1 + " " + s2;
  // }

  public String toString(){
    String s1 = Utils.formatByteArray(fileKey.getEncoded());
    String s2 = Utils.formatByteArray(hashKey.getEncoded());
    String ivString = Utils.formatByteArray(iv);
    return groupname + " " + "\nIV: " + ivString + " " + "\nFileKey: " + s1 + "\nHashKey: " + s2 + "\n";
  }

}
