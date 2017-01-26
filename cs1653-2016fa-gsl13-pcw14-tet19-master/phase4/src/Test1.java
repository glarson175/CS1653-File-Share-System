import java.security.*;
import java.util.*;

public class Test1 {

  @SuppressWarnings("unchecked")
  public static void main(String[] args) {
    Envelope e = new Envelope("Message");
    ArrayList<String> list = new ArrayList<>();
    list.add("1");
    list.add("2");
    e.addObject(list);
    Crypto crypto = new Crypto();
    Key key = crypto.generateAesKey(128);
    byte[] bytes = FileClient.serialize(e);
    byte[] cipher = crypto.aesEncrypt(bytes, key);
    byte[] text = crypto.aesDecrypt(cipher, key);
    Envelope env = (Envelope)FileClient.deserialize(text);
    System.out.println(env.getMessage());
    ArrayList<String> listr = (ArrayList<String>)env.getObjContents().get(0);
    System.out.println(list.get(1));
    System.out.println(listr.get(1));
  }
}
