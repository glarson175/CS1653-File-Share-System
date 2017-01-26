import java.io.*;
import java.math.BigInteger;


public class Utils{

  public static Object deserialize(byte[] bytes){
    try{
      ByteArrayInputStream byteInput = new ByteArrayInputStream(bytes);
      ObjectInputStream objectInput = new ObjectInputStream(byteInput);
      return objectInput.readObject();
    }
    catch(Exception e){
      System.out.println("Problem deserializing byte array!");
      return null;
    }
  }

  public static byte[] serialize(Object o){
    try{
      ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();
      ObjectOutputStream objectOutput = new ObjectOutputStream(byteOutput);
      objectOutput.writeObject(o);
      return byteOutput.toByteArray();
    }
    catch(Exception e){
      System.out.println("Problem serializing object!");
      return null;
    }
  }

  public static String formatByteArray(byte[] hash) {
    return String.format("%032X", new BigInteger(1, hash));
  }


}
