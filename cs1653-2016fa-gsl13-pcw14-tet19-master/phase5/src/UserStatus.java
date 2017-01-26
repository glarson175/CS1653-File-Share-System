import java.util.Date;

public class UserStatus {
  private String name;
  private int count;
  private boolean locked;
  private Date startTime;
  private int minutesTimeout;

  public UserStatus(String name) {
    this.name = name;
    count = 0;
    locked = false;
    startTime = null;
    minutesTimeout = 1;
  }

  public UserStatus(String name, int count, boolean locked, Date startTime, int minutesTimeout){
    this.name = name;
    this.count = count;
    this.locked = locked;
    this.startTime = startTime;
    this.minutesTimeout = minutesTimeout;
  }

  public String getName() {
    return name;
  }

  public int getFails() {
    return count;
  }

  public void resetFails() {
    count = 0;
  }

  public synchronized void addFail(){
    count++;
    if (count >= 3){
      startTimeout();
      System.out.println("Starting time out!");
    }
  }

  public boolean getLocked(){
    return locked;
  }

  public Date getStartTime() {
    return startTime;
  }

  public int getMinutesTimeout() {
    return minutesTimeout;
  }

  public synchronized boolean isLocked(){
    Date now = new Date();

    //time out has not been started
    if (startTime == null)
      return false;

    // has the timeout passed?
    if ((now.getTime() - startTime.getTime()) >= (minutesTimeout*60*1000)){
      count = 0;
      startTime = null;
      return false;
    }

    return true;
  }

  public synchronized void startTimeout() {
    Date now = new Date();
    startTime = now;
    locked = true;
  }

  public UserStatus deepCopy() {
    UserStatus copy = new UserStatus(this.name, this.count, this.locked, this.startTime, this.minutesTimeout);
    return copy;
  }

  public static UserStatus deepCopy(UserStatus status) {
    UserStatus copy = new UserStatus(status.getName(), status.getFails(), status.getLocked(), status.getStartTime(), status.getMinutesTimeout());
    return copy;
  }



}
