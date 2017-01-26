/*
Notes: In order, these are the panels that frame goes through:
mainPanel - prompts for FS and GS address and portFS
validationPanel - prompts user if they trust the public keys
loginPanel - prompts use for username and password

*/


import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.border.*;
import java.io.*;
import java.lang.NumberFormatException;
import java.security.*;
import java.nio.charset.*;
//import java.util.*;
import java.util.ArrayList;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class ClientGUI{
  private static FileClient f_client = new FileClient();
  private static GroupClient g_client = new GroupClient();
  private static Scanner keyboard = new Scanner(System.in);
	private static Crypto crypto = new Crypto();
  private String addressGS;
  private String addressFS;
  private int portGS;
  private int portFS;
  private boolean trustedFS = false;
  private boolean trustedGS = false;
  private static String username = "";
  private static UserToken token = null;
	private static Key gsKey;
	private static Key fsKey;
  private static KeyList keylist;

  private GridBagLayout gbl;
  private GridBagConstraints gbc;
  private JFrame frame;
  private JPanel mainPanel;
  private JPanel validationPanel;
  private JPanel loginPanel;
  private JPanel menuPanel;
  private JPanel actionPanel;
  private JTextField fileServerAddress;
  private JTextField fileServerPort;
  private JTextField groupServerAddress;
  private JTextField groupServerPort;
  private JButton confirmButton;
  private JButton denyButton;
  private JTextField usernameField;
  private JTextField passwordField;
  private JLabel info = new JLabel("");

  private JComboBox menuOptions;

  private static final String[] options = {"","View My Info", "Upload File", "Download File",
                              "Delete File", "List Files", "Create Group",
                              "Delete Group", "Add User to Group", "Remove User from Group",
                              "List Members of Group", "Create User", "Delete User"};
  public ClientGUI(){
    keylist = readKeyList();
    frame = new JFrame("File Sharing Fun");
    frame.setSize(800,500);
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    gbl = new GridBagLayout();
    gbc = new GridBagConstraints();
    mainPanel = new JPanel();
    mainPanel.setLayout(gbl);
    frame.add(mainPanel);
    setInitialComponents();
    //close "gracefully" on disconnecting
    frame.addWindowListener(new WindowAdapter() {
      public void windowClosing(WindowEvent e) {
        System.out.println("Closing connections gracefully.");
        if(g_client.isConnected()) g_client.disconnect();
        if(f_client.isConnected()) f_client.disconnect();
        System.exit(0);
      }
    });
    frame.setResizable(false);
    frame.setVisible(true);
  }
  //sets up the screen for mainPanel
  private void setInitialComponents(){
    System.out.println("Setting up initial components");
    JLabel prompt = new JLabel("Please enter server information.");
      Border border = prompt.getBorder();
      Border margin = new EmptyBorder(10,10,10,10);
      prompt.setBorder(new CompoundBorder(border, margin));
    JLabel fileServerLabel = new JLabel("File Server");
    JLabel groupServerLabel = new JLabel("Group Server");
    JLabel addressLabel = new JLabel("Address:");
    JLabel portLabel = new JLabel("Port:");
    JLabel addressLabel2 = new JLabel("Address:");
    JLabel portLabel2 = new JLabel("Port:");
    JLabel space = new JLabel("");
    space.setPreferredSize(new Dimension(15,15));
    fileServerAddress = new JTextField(12);
    fileServerPort = new JTextField(6);
    groupServerAddress = new JTextField(12);
    groupServerPort = new JTextField(6);
    JButton connectButton = new JButton("Connect");

    addComponent(1,0,2,1,mainPanel,prompt);
    //group server labels
    addComponent(1,1,1,1,mainPanel, groupServerLabel);
    addComponent(0,2,1,1,mainPanel, addressLabel2);
    addComponent(1,2,1,1,mainPanel, groupServerAddress);
    addComponent(2,2,1,1,mainPanel, portLabel2);
    addComponent(3,2,1,1,mainPanel, groupServerPort);
    //file server labels
    addComponent(1,3,1,1,mainPanel, fileServerLabel);
    addComponent(0,4,1,1,mainPanel, addressLabel);
    addComponent(1,4,1,1,mainPanel, fileServerAddress);
    addComponent(2,4,1,1,mainPanel, portLabel);
    addComponent(3,4,1,1,mainPanel, fileServerPort);
    //add connect button
    addComponent(1,5,1,1,mainPanel, space);
    addComponent(1,6,1,1,mainPanel, connectButton);

    connectButton.addActionListener(connect());

  }
  //helper method that adds a component to gridbaglayout
  private void addComponent(int x, int y, int w, int h, Container aContainer, Component aComponent){
    gbc.gridx = x;
    gbc.gridy = y;
    gbc.gridwidth = w;
    gbc.gridheight= h;
    gbl.setConstraints(aComponent, gbc);
    aContainer.add(aComponent);
  }
  //connects to servers based on address and ports
    //uses the default address and ports if empty or if there are errors
  private ActionListener connect(){
    ActionListener action = new ActionListener(){
      public void actionPerformed(ActionEvent ae){
        addressFS = fileServerAddress.getText();
        if(addressFS.equals("")) addressFS = "localhost";
        String port = fileServerPort.getText();
        try{
          portFS = Integer.parseInt(port);
        } catch(Exception e){
          portFS = FileServer.SERVER_PORT;
        }
        addressGS = groupServerAddress.getText();
        if(addressGS.equals("")) addressGS = "localhost";
        String port2 = groupServerPort.getText();
        try{
          portGS = Integer.parseInt(port2);
        } catch(Exception e){
          portGS = GroupServer.SERVER_PORT;
        }
        System.out.println("Connecting to file server: " + addressFS + " at port " + portFS);
        System.out.println("Connecting to group server: " + addressGS + " at port " + portGS);
        if(f_client.connect(addressFS, portFS) && g_client.connect(addressGS, portGS)){
          validationScreen();
        }
        else{
          JLabel error = new JLabel("Invalid address/ports");
          error.setForeground(Color.red);
          addComponent(1,5,1,1,mainPanel, error);
          frame.invalidate();
          frame.validate();
          if(g_client.isConnected())g_client.disconnect();
          if(f_client.isConnected())f_client.disconnect();
        }
      }
    };
    return action;
  }
  //draws the screen that displays and prompts the user if they trust public keys
  private void validationScreen(){
    System.out.println("Moving to validation screen");
    frame.remove(mainPanel);
    validationPanel = new JPanel();
    gbl = new GridBagLayout();
    validationPanel.setLayout(gbl);
    JLabel prompt = new JLabel("Please confirm the following keys:");
    addComponent(0,0,1,1,validationPanel, prompt);
    gsKey = g_client.getGSKey();
    fsKey = f_client.getFSKey();
    //check to see if keys are trusted
    //see if GS key is safe
    if (!(keylist.isEmpty())) {
     trustedGS = keylist.isTrustedKey(addressGS, portGS, gsKey);
    }
    if(!trustedGS){
      JLabel gsKeyLabel = new JLabel("Verify Group Server Public Key:", SwingConstants.CENTER);
      addComponent(0,1,1,1,validationPanel, gsKeyLabel);
      JTextArea gsKeyText = new JTextArea(5,50);
      gsKeyText.setText(Base64.getEncoder().encodeToString(gsKey.getEncoded()));
      gsKeyText.setWrapStyleWord(true);
      gsKeyText.setLineWrap(true);
      addComponent(0,2,1,1,validationPanel, gsKeyText);
    }
    else {
      System.out.println("Address:Key of GS has previously been saved as trusted.");
    }
    //see if FS key is safe
    if(!(keylist.isEmpty())){
      trustedFS = keylist.isTrustedKey(addressFS, portFS, fsKey);
    }
    if(!trustedFS){
      JLabel fsKeyLabel = new JLabel("Verify File Server Public Key:", SwingConstants.CENTER);
      addComponent(0,3,1,1,validationPanel, fsKeyLabel);
      JTextArea fsKeyText = new JTextArea(5,50);
      fsKeyText.setText(Base64.getEncoder().encodeToString(fsKey.getEncoded()));
      fsKeyText.setWrapStyleWord(true);
      fsKeyText.setLineWrap(true);
      addComponent(0,4,1,1,validationPanel, fsKeyText);
    }
    else{
      System.out.println("Address:Key of FS has previously been saved as trusted.");
    }
    JPanel row = new JPanel();
    confirmButton = new JButton("Confirm");
    confirmButton.addActionListener(confirm());
    denyButton = new JButton("Deny");
    denyButton.addActionListener(confirm());
    row.add(confirmButton);
    row.add(denyButton);
    addComponent(0,5,1,1, validationPanel, row);
    frame.add(validationPanel);
    frame.invalidate();
    frame.validate();
    if(trustedFS && trustedGS){
      System.out.println("Both keys are saved as trusted! Going straight to login screen.");
      loginScreen();
    }
  }
  //method that resets the connections of the client in the case of an untrusted key
  private void reset(){
    System.out.println("Disconnecting stuff");
    if(g_client.isConnected())g_client.disconnect();
    if(f_client.isConnected())f_client.disconnect();
    g_client = new GroupClient();
    f_client = new FileClient();
    try{
      frame.remove(validationPanel);
      frame.remove(menuPanel);
    } catch(Exception e){}
    mainPanel = new JPanel();
    gbl = new GridBagLayout();
    mainPanel.setLayout(gbl);
    setInitialComponents();
    //System.out.println("Returning to main panel");
    frame.add(mainPanel);
    frame.invalidate();
    frame.validate();
  }
  //action listener that handles whether or not if a user trusts public keys
  private ActionListener confirm(){
    ActionListener action = new ActionListener(){
      public void actionPerformed(ActionEvent ae){
        if(ae.getSource() == confirmButton){
          if(!trustedFS){
            System.out.println("Saving FS key to keylist.");
            keylist.addKey(addressFS, portFS, fsKey);
            saveKeyList();
          }
          if(!trustedGS){
            System.out.println("Saving GS key to keylist.");
            keylist.addKey(addressGS, portGS, gsKey);
            saveKeyList();
          }
          System.out.println("Test point 2: Confirmed keys. Moving on to authentcation");
          loginScreen();
        }
        else if(ae.getSource() == denyButton){
          System.out.println("Test point 3: Denied one key. Resetting.");
          reset();
        }
      }
    };
    return action;
  }
  //method that sets up the screen that prompts for username and password
  private void loginScreen(){
    //Not sure where else to put this
    if(!authenticateFileServer()){
      System.out.println("Something went wrong when trying to authenticate File Server!");
      reset();
    }
    else{
      System.out.println("Successfully Authenticated File Server!");
    }
    frame.remove(validationPanel);
    loginPanel = new JPanel();
    gbl = new GridBagLayout();
    loginPanel.setLayout(gbl);
    JLabel prompt = new JLabel("Please input user information:", SwingConstants.CENTER);
    prompt.setPreferredSize(new Dimension(200,60));
    JLabel userLabel = new JLabel("Username:");
    usernameField = new JTextField(20);
    JLabel passwordLabel = new JLabel("Password:");
    passwordField = new JTextField(20);
    JLabel space = new JLabel("");
    space.setPreferredSize(new Dimension(15,15));
    JButton loginButton = new JButton("Login");
    loginButton.addActionListener(login());
    addComponent(1,0,1,1, loginPanel, prompt);
    addComponent(0,2,1,1, loginPanel, userLabel);
    addComponent(1,2,2,1, loginPanel, usernameField);
    addComponent(0,3,1,1, loginPanel, passwordLabel);
    addComponent(1,3,2,1, loginPanel, passwordField);
    addComponent(0,4,1,1, loginPanel, space);
    addComponent(1,5,1,1, loginPanel, loginButton);
    frame.add(loginPanel);
    frame.invalidate();
    frame.revalidate();
  }
  //validates username and password from login
  private ActionListener login(){
    ActionListener action = new ActionListener(){
      public void actionPerformed(ActionEvent ae){
        System.out.println("Trying to validate.");
        username = usernameField.getText();
        String password = passwordField.getText();
        token=g_client.authenticate(username,password);
        if(token !=null){
          System.out.println("Successful authentication");
          menuScreen();
        }
        else{
          JLabel error = new JLabel("Invalid username/password.");
          error.setForeground(Color.red);
          addComponent(1,4,1,1, loginPanel, error);
          frame.invalidate();
          frame.validate();
        }
      }
    };
    return action;
  }
  //sets up menu screen
  @SuppressWarnings("unchecked")
  private void menuScreen(){
    frame.remove(loginPanel);
    menuPanel = new JPanel();
    gbl = new GridBagLayout();
    menuPanel.setLayout(gbl);
    JLabel prompt = new JLabel("Select an Action: ");
    addComponent(0,0,1,1,menuPanel, prompt);
    //drop down menu for options
    menuOptions = new JComboBox(options);
    menuOptions.setSelectedIndex(0);
    menuOptions.addActionListener(menuAction());
    addComponent(1,0,1,1,menuPanel, menuOptions);

    actionPanel = new JPanel();
    actionPanel.setLayout(gbl);
    actionPanel.setBackground(Color.WHITE);
    addComponent(0,1,5,5, menuPanel, actionPanel);

    JButton logoutButton = new JButton("Logout");
    logoutButton.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          reset();
        }
      }
    );
    addComponent(1,6,1,1, menuPanel,logoutButton);
    frame.add(menuPanel);
    frame.invalidate();
    frame.revalidate();
  }

  private ActionListener menuAction(){
		ActionListener action = new ActionListener() {
			public void actionPerformed(ActionEvent e){
				JComboBox cb = (JComboBox)e.getSource();
        String choice = (String)cb.getSelectedItem();
        System.out.println("You selected " + choice);
        switch(choice){
          case "View My Info":
            token = g_client.getToken(username);
            viewInfo();
            break;
          case "Upload File":
            token = g_client.getToken(username);
            uploadFile();
            break;
          case "Download File":
            downloadFile();
            break;
          case "Delete File":
            deleteFile();
            break;
          case "List Files":
            listFiles();
            break;
          case "Create Group":
            createGroup();
            token = g_client.getToken(username);
            break;
          case "Delete Group":
            deleteGroup();
            token = g_client.getToken(username);
            break;
          case "Add User to Group":
            addUserToGroup();
            token = g_client.getToken(username);
            break;
          case "Remove User from Group":
            deleteUserFromGroup();
            token = g_client.getToken(username);
            break;
          case "List Members of Group":
            listMembers();
            break;
          case "Create User":
            createUser();
            break;
          case "Delete User":
            deleteUser();
            break;
          default:
            resetActionPanel();
            System.out.println("Back to default.");
            break;
        }
			}
		};
		return action;
	}




// Menu item handlers ----------------------------------------
  private void resetActionPanel(){
    actionPanel.removeAll();
    frame.invalidate();
    frame.revalidate();
  }
  private void viewInfo(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to View Your Info");
    addComponent(0,0,1,1,actionPanel,prompt);
    String[] tokens = token.toString().split("; ");
    JLabel issuer = new JLabel(tokens[0]);
    addComponent(0,1,1,1,actionPanel, issuer);
    JLabel subject = new JLabel(tokens[1]);
    addComponent(0,2,1,1,actionPanel, subject);
    JLabel groups = new JLabel(tokens[2]);
    addComponent(0,3,1,1,actionPanel, groups);
    frame.invalidate();
    frame.revalidate();
  }
  private void uploadFile(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Upload a File");
    addComponent(0,0,1,1,actionPanel,prompt);
    JLabel sourceLabel = new JLabel("File source:");
    addComponent(0,1,1,1,actionPanel, sourceLabel);
    JTextField sourceField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, sourceField);
    JLabel destinationLabel = new JLabel("File destination:");
    addComponent(0,2,1,1,actionPanel, destinationLabel);
    JTextField destinationField = new JTextField(20);
    addComponent(1,2,1,1,actionPanel, destinationField);
    JLabel groupnameLabel = new JLabel("Group:");
    addComponent(0,3,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,3,1,1,actionPanel, groupnameField);
    JButton submit = new JButton("Upload File");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String source = sourceField.getText();
          String dest = destinationField.getText();
          String group = groupnameField.getText();
					//Checker to see if the user belongs to the group they're trying to upload to
					String[] tokens = token.toString().split("; ");
					if(tokens[2].contains(group)){
						if(source.length() == 0 || dest.length() == 0 || group.length() ==0){
							JOptionPane.showMessageDialog(frame, "Error: One or more input is empty.");
						}
						else{
							try{
								//Checker to see if the file exists (can remove later)
								File f = new File(source);
								if(f.exists()){
									ShareFile file = new ShareFile(username, group, source);
									if(f_client.upload(source, dest, group, token)){
										JOptionPane.showMessageDialog(frame, "Success uploading file.");
										uploadFile();
									}
									else{
										JOptionPane.showMessageDialog(frame, "Failed to upload file.");
										uploadFile();
									}
								}
								else{
									JOptionPane.showMessageDialog(frame, "File you're trying to upload does not exist. Try again.");
									uploadFile();
								}
							}
							catch(Exception ex){
								JOptionPane.showMessageDialog(frame, "Error: " + ex.toString());
								uploadFile();
							}
						}//end of else for source/dest/group length = 0 case
					}
					else{ //user does not belong to group
						JOptionPane.showMessageDialog(frame, "You do not belong to this group");
						uploadFile();
					}
        }
      }
    );
    addComponent(0,4,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  @SuppressWarnings("unchecked")
  private void downloadFile(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Download a File");
    addComponent(0,0,1,1,actionPanel,prompt);
    /*JLabel sourceLabel = new JLabel("Filename:");
    addComponent(0,1,1,1,actionPanel, sourceLabel);
    JTextField sourceField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, sourceField);*/
    JLabel destinationLabel = new JLabel("File destination:");
    addComponent(0,1,1,1,actionPanel, destinationLabel);
    JTextField destinationField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, destinationField);

    ArrayList<String> files = (ArrayList)f_client.listFiles(token);
    Object[] data = files.toArray();
    JList list = new JList(data); //data has type Object[]
    list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
    list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
    list.setVisibleRowCount(-1);
    addComponent(0,2,2,10,actionPanel,list);

    JButton submit = new JButton("Download");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
        //  String filename = sourceField.getText();
          if(!list.isSelectionEmpty()){
            String filename = (String)(list.getSelectedValue());
            String dest = destinationField.getText();
            if(filename.length() == 0 || dest.length() == 0){
              JOptionPane.showMessageDialog(frame, "Error: One or more input is empty.");
            }
            else{
              if(f_client.download(filename, dest, token)){
                JOptionPane.showMessageDialog(frame, "Success downloading file.");
                downloadFile();
              }
              else{
                JOptionPane.showMessageDialog(frame, "Failed to download file.");
                downloadFile();
              }
            }
          }
          else{
            System.out.println("Selection is empty, refusing to do anything.");
          }
        }
      }
    );
    addComponent(0,12,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  @SuppressWarnings("unchecked")
  private void deleteFile(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Delete a File");
    addComponent(0,0,1,1,actionPanel,prompt);
    /*
    JLabel sourceLabel = new JLabel("Filename:");
    addComponent(0,1,1,1,actionPanel, sourceLabel);
    JTextField sourceField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, sourceField);
    */
    ArrayList<String> files = (ArrayList)f_client.listFiles(token);
    Object[] data = files.toArray();
    JList list = new JList(data); //data has type Object[]
    list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
    list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
    list.setVisibleRowCount(-1);
    addComponent(0,1,1,10,actionPanel,list);
    JButton submit = new JButton("Delete");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          if(!list.isSelectionEmpty()){
            //String filename = sourceField.getText();
            String filename = (String)(list.getSelectedValue());

            if(filename.length() == 0){
              JOptionPane.showMessageDialog(frame, "Invalid Input: Input is empty.");
            }
            else{
              if(f_client.delete(filename, token)){
                JOptionPane.showMessageDialog(frame, "Success deleting file.");
                deleteFile();
              }
              else{
                JOptionPane.showMessageDialog(frame, "Failed to delete file.");
                deleteFile();
              }
            }
          }
          else{
            System.out.println("Selection is empty, refusing to do anything!");
          }
        }
      }
    );
    addComponent(0,12,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }

  @SuppressWarnings("unchecked")
  private void listFiles(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to List Files");
    addComponent(0,0,1,1,actionPanel,prompt);
    ArrayList<String> files = (ArrayList)f_client.listFiles(token);
    Object[] data = files.toArray();
    JList list = new JList(data); //data has type Object[]
    list.setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
    list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
    list.setVisibleRowCount(-1);
    addComponent(0,1,1,6,actionPanel,list);
        /*
    if(files != null){
      for(int i=0;i<files.size();i++){
        JLabel file = new JLabel(files.get(i));
        addComponent(0,i+1,1,1,actionPanel,file);
      }
    }
    */
    frame.invalidate();
    frame.revalidate();
  }

  private void createGroup(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Create a Group");
    addComponent(0,0,2,1,actionPanel,prompt);
    JLabel groupnameLabel = new JLabel("Name of new group:");
    addComponent(0,1,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, groupnameField);
    JButton submit = new JButton("Create Group");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String groupname = groupnameField.getText();
          if(g_client.createGroup(groupname, token)){
            JOptionPane.showMessageDialog(frame, "Success creating new group.");
            createGroup();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to create group.");
            createGroup();
          }
        }
      }
    );
    addComponent(0,2,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  private void deleteGroup(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Delete a Group");
    addComponent(0,0,2,1,actionPanel,prompt);
    JLabel groupnameLabel = new JLabel("Name of group to delete:");
    addComponent(0,1,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, groupnameField);
    JButton submit = new JButton("Delete Group");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String groupname = groupnameField.getText();
          if(g_client.deleteGroup(groupname, token)){
            JOptionPane.showMessageDialog(frame, "Successfully deleted group.");
            deleteGroup();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to delete group.");
            deleteGroup();
          }
        }
      }
    );
    addComponent(0,2,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  private void addUserToGroup(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Add a User to Group");
    addComponent(0,0,1,1,actionPanel,prompt);
    JLabel usernameLabel = new JLabel("User:");
    addComponent(0,1,1,1,actionPanel, usernameLabel);
    JTextField usernameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, usernameField);
    JLabel groupnameLabel = new JLabel("Group:");
    addComponent(0,2,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,2,1,1,actionPanel, groupnameField);
    JButton submit = new JButton("Add User");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String name = usernameField.getText();
          String groupname = groupnameField.getText();
          if(g_client.addUserToGroup(name, groupname, token)){
            JOptionPane.showMessageDialog(frame, "Success adding user to group.");
            addUserToGroup();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to add user to group.");
            addUserToGroup();
          }
        }
      }
    );
    addComponent(0,3,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  private void deleteUserFromGroup(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Remove a User from Group");
    addComponent(0,0,1,1,actionPanel,prompt);
    JLabel usernameLabel = new JLabel("User:");
    addComponent(0,1,1,1,actionPanel, usernameLabel);
    JTextField usernameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, usernameField);
    JLabel groupnameLabel = new JLabel("Group:");
    addComponent(0,2,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,2,1,1,actionPanel, groupnameField);
    JButton submit = new JButton("Remove User");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String name = usernameField.getText();
          String groupname = groupnameField.getText();
          if(g_client.deleteUserFromGroup(name, groupname, token)){
            JOptionPane.showMessageDialog(frame, "Success removing user from group.");
            deleteUserFromGroup();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to remove user from group.");
            deleteUserFromGroup();
          }
        }
      }
    );
    addComponent(0,3,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  @SuppressWarnings("unchecked")
  private void listMembers(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to List Members of a Group");
    addComponent(0,0,3,1,actionPanel,prompt);
    JLabel groupnameLabel = new JLabel("Group:");
    addComponent(0,1,1,1,actionPanel, groupnameLabel);
    JTextField groupnameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, groupnameField);
    JPanel groupPanel = new JPanel();
    groupPanel.setMinimumSize(new Dimension(300,200));
    groupPanel.setBackground(Color.white);
    addComponent(0,2,3,3,actionPanel, groupPanel);
    JButton submit = new JButton("List");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          groupPanel.removeAll();
          String groupname = groupnameField.getText();
          ArrayList<String> members = (ArrayList)g_client.listMembers(groupname, token);
          if(members != null){
            System.out.println("Members: " + members.toString());
            JLabel memberLabel= new JLabel(members.toString());
            groupPanel.add(memberLabel);
          }
          else{
            JLabel memberLabel = new JLabel("No members in group");
            groupPanel.add(memberLabel);
          }
          frame.invalidate();
          frame.revalidate();
        }
      }
    );
    addComponent(2,1,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  private void createUser(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Create a User");
    addComponent(0,0,1,1,actionPanel,prompt);
    JLabel usernameLabel = new JLabel("New Username:");
    addComponent(0,1,1,1,actionPanel, usernameLabel);
    JTextField usernameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, usernameField);
    JLabel passwordLabel = new JLabel("Password:");
    addComponent(0,2,1,1,actionPanel, passwordLabel);
    JTextField passwordField = new JTextField(20);
    addComponent(1,2,1,1,actionPanel, passwordField);
    JButton submit = new JButton("Create User");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String name = usernameField.getText();
          String password = passwordField.getText();
          if(g_client.createUser(name, password, token)){
            JOptionPane.showMessageDialog(frame, "Success creating new user.");
            createUser();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to create user.");
            createUser();
          }
        }
      }
    );
    addComponent(0,3,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }
  private void deleteUser(){
    actionPanel.removeAll();
    JLabel prompt = new JLabel("You Selected to Delete a User");
    addComponent(0,0,1,1,actionPanel,prompt);
    JLabel usernameLabel = new JLabel("User to Delete:");
    addComponent(0,1,1,1,actionPanel, usernameLabel);
    JTextField usernameField = new JTextField(20);
    addComponent(1,1,1,1,actionPanel, usernameField);
    JButton submit = new JButton("Delete User");
    submit.addActionListener(new ActionListener()
      {
        public void actionPerformed(ActionEvent e){
          String name = usernameField.getText();
          if(g_client.deleteUser(name, token)){
            JOptionPane.showMessageDialog(frame, "Success deletion of user.");
            deleteUser();
          }
          else{
            JOptionPane.showMessageDialog(frame, "Failed to delete user.");
            deleteUser();
          }
        }
      }
    );
    addComponent(0,2,2,1,actionPanel, submit);
    frame.invalidate();
    frame.revalidate();
  }


  //STUFF FOR DOING KEY STUFF----------------------------------
  public static void saveKeyToFile(Key k, String address, int port) {
    ObjectOutputStream outStream = null;
    FileOutputStream fos = null;
    try
    {
      fos = new FileOutputStream("TrustedKeys.bin");
      outStream = new ObjectOutputStream(fos);
      outStream.writeObject(address);
      outStream.writeObject(port);
      outStream.writeObject(k);
      System.out.println("Successfully wrote to TrustedKeys.bin");
    }
    catch(Exception e)
    {
      System.out.println("Error Saving key to file " + e.getMessage());
      e.printStackTrace();
    }
    // Ensure streams are clsoed
    finally {
      try { if (outStream != null) outStream.close();
      } catch(IOException e){}
      try { if (fos!= null) fos.close();
      } catch (IOException e){}
    }
  }

  public static KeyList readKeyList() {
    ObjectInputStream fileStream = null;
    FileInputStream fis = null;
    try
    {
      fis = new FileInputStream("TrustedKeys.bin");
      fileStream = new ObjectInputStream(fis);
      keylist = (KeyList)fileStream.readObject();
      System.out.println("Read key list");
    }
    catch (FileNotFoundException e) {
      keylist = new KeyList();
      System.out.println("Creating new key list");
    }
    catch (Exception e) {
      System.out.println("Problem reading from TrustedKeys.bin");
      e.printStackTrace();
    }
    finally {
      if (fis != null){
        try { fis.close(); }
        catch (IOException e) {}
      }
      if (fileStream != null) {
        try {fileStream.close();}
        catch (IOException e) {}
      }
    }
    return keylist;
  }

  public static void saveKeyList() {
    ObjectOutputStream outStream = null;
    try  {
      outStream = new ObjectOutputStream(new FileOutputStream("TrustedKeys.bin"));
      outStream.writeObject(keylist);
      System.out.println("Saved TrustedKeys.bin");
    }
    catch (Exception e) {
      System.out.println("Problem writing to TrustedKeys.bin");
      e.printStackTrace();
    }
    finally {
      try {outStream.close();}
      catch (IOException e) {};
    }
  }

public static boolean authenticateFileServer() {
    boolean trusted = false;
    try{
      // this only authenticates the server, not the client.
      // client authentication happens with requets
      trusted = f_client.authenticate();

    }
    catch (IOException e){};
    return trusted;

  }
}
