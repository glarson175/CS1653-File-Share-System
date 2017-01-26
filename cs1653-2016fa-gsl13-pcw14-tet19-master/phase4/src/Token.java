import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.util.*;
import java.security.*;
import java.util.Base64;
import java.math.BigInteger;

public class Token implements UserToken, java.io.Serializable  {

  private final String issuer;
  private final String subject; //The name of the person who recieves the token
  private final List <String> groups;
  private static final long serialVersionUID = 843718676814078905L;

  // Tokens are created for use on only one file server which will be identified
  // by the hash of its public key
  private byte[] fileServerID = null;
  private byte[] signature = null;

  public Token(String issuer, String subject, List<String> groups){
    this.issuer = issuer;
    this.subject = subject;
    this.groups = groups;
  }

  public Token(String issuer, String subject, List<String> groups, byte[] fileServerID){
    this(issuer, subject, groups);
    this.fileServerID = fileServerID;
  }


  public Token(String issuer, String subject, List<String> groups,
                 byte[] fileServerID, byte[] signature) {
    this(issuer, subject, groups, fileServerID);
    this.signature = signature;
  }

  public String getIssuer(){
    return issuer;
  }

  public String getSubject(){
    return subject;
  }

  public List<String> getGroups(){
    return groups;
	}

  public byte[] getSignature(){
    return signature;
  }

  public byte[] getFileServerID() {
    return fileServerID;
  }

  public String toString() {
    groups.sort(String::compareToIgnoreCase);
    StringBuilder tokenStr = new StringBuilder();
    tokenStr.append("Issuer: " + issuer + "; Subject: " + subject + "; Groups: ");
    for (String groupName : groups)
      tokenStr.append(groupName + ", ");
    // tokenStr.append("\nFileServerID: " + Arrays.toString(fileServerID));
    tokenStr.append("\nFileServerID: " + Utils.formatByteArray(fileServerID));
    return tokenStr.toString();
  }


  public UserToken deepCopy(UserToken token){
    String issuer = token.getIssuer();
    String subject = token.getSubject();
    List<String> groups = new ArrayList<String>(token.getGroups());
    byte[] sig = token.getSignature();
    byte[] fsID = token.getFileServerID();
    UserToken copy = new Token(issuer, subject, groups, fsID, sig);
    //UserToken copy = new Token(issuer, subject, groups, sig);
    return copy;
  }

  public boolean signToken(PrivateKey key){
    Crypto crypto = new Crypto();
    byte[] tokenHash = crypto.hashSHA_256(this.toString());
    if (tokenHash == null) return false;
    signature = crypto.signRSA(tokenHash, key);
    return true;
  }


}
