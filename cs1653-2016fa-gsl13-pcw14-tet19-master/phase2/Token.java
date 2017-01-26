import java.util.List;

public class Token implements UserToken, java.io.Serializable  {

  private final String issuer;
  private final String subject; //The name of the person who recieves the token
  private final List <String> groups;
  private static final long serialVersionUID = 843718676814078905L;

  public Token(String issuer, String subject, List<String> groups){
    this.issuer = issuer;
    this.subject = subject;
    this.groups = groups;
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



}
