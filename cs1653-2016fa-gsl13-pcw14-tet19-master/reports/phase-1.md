#Phase 1 - Written Report
##Group Information
Gabriel Larson - gsl13@pitt.edu <br/>
Pauline Walsh - pcw14@pitt.edu <br />
Terry Tan - tet19@pitt.edu

##Section 1: Security Properties
<!-- //TO-DO: Aim to have 15-20 properties at least (6 per person = 18 total) -->
<!-- General Format: * <b>Property 1: Property_Name.</b> Description here. -->

<!-- REMEMBER: each property should include:
(i) a name for the property,
(ii) a definition of what this property entails,
(iii) a short description of why this property is
important
(iv) any assumptions upon which this property depends.
-->

<!-- Ideas (from Terry):
    Verification - (file is sent from trusted sender)
    Data Confidentiality -(intercepted data cannot be read)
    User Authentication - user provides ID and proof to get tokens
    separation of privilege for something?
-->

<!-- Ideas from Pauline:
    Accessibility
    Data confidentiality during storage (as well as during transmission)
-->

<!-- Model clarification:
model components: "entities of the system and how they're going to behave"
Entities would include: users/client, file servers, group servers, network, and other entities that may or may not be able to see that network
the trust assumptions are assumptions we have to make for the entities, like training/intent of users, privacy of the network, etc.
-->


<!-- Properties 1-6 written by Gabe -->

* <b>Property 1: User Safety.</b> User Safety states that a user u is the only person capable to delete user u. This is necessary to ensure a user account can only be deleted with that user's permission. This allows a user to be the sole owner of their account.

* <b>Property 2: User Verification.</b> User Verification states that the users must log on to the system and will be verified with a username and password. This is necessary so that the only the correct combination of username and password allows access to the user account. This further allows the user to be the sole person to their account.

* <b>Property 3: Addition to a Group.</b> Addition to a Group states that a user u can add another user v to group g if and only if user u is a member of group g. This is dependent on the assumption that group administrators do not have malicious and will only add trustworthy users to the group. This is necessary for the whole idea behind group file sharing.

* <b>Property 4: File Consistency.</b> File Consistency states that changes made to files within a group are visible to all members immediately. This would allow users to overwrite previous changes to files and is dependent on the assumption that users are going to be responsible about managing the content of files.

* <b>Property 5: Removal from Group.</b> Removal from Group states that a user u may remove a user v from group g provided users u and v are both in the group, and user u has the support of at least one other group member that agrees user v should be removed. This is necessary in case of malicious activities from a group member and provides some security for user v that two or more must agree to remove them.

* <b>Property 6: Group Safety.</b> Group Safety states that a group g can only be deleted by the collective effort of every user in g. This ensures that any single malicious user can not remove an entire group and all files included in that group. This is necessary to protect the idea of group file sharing where users can be separated into distinct groups.  

<!--Properties 7-12 written by Pauline-->
<!--TODO: add assumptions to properties -->
* <b>Property 7: Data Confidentiality.</b> Data confidentiality has two components. It states that the contents of a file intercepted during transmission between the server and client should be unrecoverable to an attacker. It also states that an attacker that breaches the file server should be unable to read the contents of the files stored there. This second component is only necessary for the most sensitive files--for example, files containing passwords or financial data. The encryption during file transfer might not be needed on a private network, assuming that no malicious persons have gained access to that network, but is important for transferring files across public networks.

* <b>Property 8: Data Integrity.</b> Data Integrity states that a file should not change while traveling between the server and the client or vice versa. If the file has changed, it should be rejected by the recipient. This is important to prevent malicious manipulation of file contents.

* <b>Property 9: Authenticated File Server.</b> The client should have a way to authenticate the file server (probably through the existence of a digital certificate on the server which has been signed by a Certification Authority.<sup>6</sup>) This is important to prevent an attacker from serving malicious files and to prevent them from improperly gaining access to files uploaded by users.

* <b>Property 10: Transaction History.</b> Group administrators should be able to access a history of file uploads/downloads/modifications/deletions. This is important in providing accountability and to provide auditing capabilities which may be required to prove compliance with legal regulations (HIPAA compliance, PCI DSS, etc.). This property assumes that there is a system in place to determine who can be trusted with administrative privileges. "Trust" is an ambiguous term, and the methods used to ensure the administrator is trusted will vary depending on the environment--from the rigorous background checks and regular audits required in military or defense settings, to the less thorough background checks required by some corporations, to the more informal chains of trust that can be formed by people "vouching" or providing references for each other.

* <b>Property 11: Usability (Psychological Acceptability<sup>2</sup>).</b> Usability states that security mechanisms should be easy for the users to apply. This is important because if the security mechanisms are too difficult to use, the users may apply them incorrectly or fail to use them at all.

* <b>Property 12: Mandatory Security Mechanisms.</b> Mandatory Security Mechanisms states that the group administrator should be able to enforce the use of certain security mechanisms (such as encrypted file storage/transfer or password rules) by all group members. This is important because in certain environments properties like data confidentiality and integrity may be vital for such purposes as preventing state or corporate espionage or to comply with legal regulations.


<!-- Properties 13-18 written by Terry-->
* <b>Property 13: Permission Levels.</b> Permissions levels state that permissions are grouped into specific classes that are assigned to users. This is important, because it reduces the redundancy of listing every permission for every user.

* <b>Property 14: Default Minimum Privilege (Least Privilege).</b> Default minimum privilege states that a new user defaults to a set of limited or no permissions and access. This property is important, because without it, a new user could have possibly have access or the ability to edit files. This property assumes that actions can only be done if one has been given permission/privilege to do so.<sup>2</sup>

* <b>Property 15: Different Permissions for Different Groups.</b> This states that for every group g, every user should not have the same permission for every group unless explicitly given so. Without this, a person with high privileges in one group could wreck havoc in another group.

* <b>Property 16: Correct Token.</b> This states that tokens must be checked to make sure that they are "correct". Without this, if someone gets the wrong token, they could end up with permissions that they should not have, such as editing a file.

* <b>Property 17: Token Expiration.</b> Token expiration states that if a token t is given to a user, token t must expire after a specified amount of time. Without this, someone could have permanent access after authenticating only once, and if the token is stolen, would at least not be viable to use for an extended period of time.<sup>1</sup>

* <b>Property 18: Token for Every Request.</b> This states that every request or access made to a file server requires token(s) to be sent with it. Without this, someone claiming to be a user with proper permissions can have access to files they should not. This property assumes the principle of Complete Mediation is in effect.<sup>2</sup>

* <b>Property 19: Group Owner.</b> Every group g should have an owner p', designated as by default as the creator of the group. Ownership can change, but the group owner is the sole person who can add/remove users and delete the group. Without this, group users may be able to add other users to groups with highly sensitive information.

<br />
##Section 2: Threat Models
<!--//TO-DO: 2-3 Threat Models
  //3 if using the example given in class -->

<!-- Gabe's Model -->
* <b>Model 1: Intra-office Protected Subnet</b><sup>3</sup>
  * The system will be deployed within a small organization to facilitate file sharing between members of the technical staff. All servers will be operated on a subnet that can only be accessed from a wired connection inside of the office building, and only machines whose MAC addresses have been explicitly authorized can connect to these wired ports.
  * Trust Assumptions: It is assumed that only members of the technical staff can listen to communications on this subnet, and that servers on this subnet cannot communicate with the broader Internet.
  * Security Properties
    * Property 2: User Verification. We would want this property so that only verified users can access the company network
    * Property 4: File Consistency. We would want this property to ensure that users within a group are kept up to date on file content.
    * Property 8: Data Integrity. We need this property to ensure even malicious users within the subnet cannot intercept and change data.
    * Property 10: Transaction History. We need this to allow group users to see the activity of a group.
    * Property 15: Different Permissions for Different Groups. We need this so that users do not exceed their desired permissions inside a given group
    * Property 18: Token for Every Request. We need this to again ensure that no user does anything outside of their desired permissions.


<!-- Pauline's Model -->
<!-- Should group server be accessible from outside? -->
<!-- Are the trust assumptions the vulnerabilities and the security properties the countermeasures?-->
* <b>Threat Model 2: File system for a large corporation with an international presence (offices in several different countries)</b>
  * This system will consist of several (10-20) file servers and a group server on a private network. The file servers will be used by a wide variety of departments such as Human Resources, Marketing, Engineering, Sales, Accounting, IT, and so on. Sensitive financial data related to sales and accounting is stored on the servers. There is also data related to patented engineering processes on the servers. The file servers are accessible from outside of the private network using a public address. The network is protected by a hardware firewall which limits incoming connections to a specific port which is open to allow connections to the file servers. Authentication is required immediately upon connecting to the server from outside of the private network, and the connection will be closed if the authentication fails. The network is also protected by the use of a proxy server which prevents users from connecting to web addresses which pose known or probable threats to the security of the network (viruses, malware, etc.). Groups are managed on the group server, all authorized users belong to a group, and group policies exist to manage both access rights and privilege levels based on employee job titles.
  * Trust Assumptions:  It is assumed that users of the system have had a level of trust established which is in proportion to the access rights and privilege levels of the group to which they belong. This trust might be established through hiring practices (background checks), security clearance levels, and periodic audits of the system. It is assumed that group administrators will follow company policy regarding security practices--that is, will not create vulnerabilities through maliciousness, laziness, or incompetence. It is assumed that users will keep their account credentials private. However, human behavior cannot be predicted with certainty, and so it cannot be assumed that the file servers on the private network are impossible to breach.
  * Security Properties
    * Property 2: User Verification. All employees accessing the file server need to be authenticated to ensure they have the correct permissions.
    * Property 7: Data Confidentiality. Certain types of files should not be readable by users that have not been explicitly granted permission to do so (especially the account credentials lists which exists on the group server).
    * Property 8: Data Integrity. It will be important to ensure the integrity of certain types of files, such as those relating to payroll, accounting, and engineering. This will prevent both malicious tampering (changing pay rate, for example), as well as ensuring that files are not accidentally corrupted during transmission.
    * Property 9: Authenticated File Server. Clients will be connecting to the file server from outside the network and need to be able to verify its identity.
    * Property 10: Transaction History. This is important to provide internal auditing capabilities in order to verify the security of the file servers. Also, credit card information is stored on the servers in this model, and it's a requirement  to track access to network resources in order to to be in compliance with the Payment Card Industry Data Security Standard (PCI DSS)<sup>5></sup>.
    * Property 11: Usability. The user is the weak link in any security system, so employees should be trained on the importance of data security and how to implement security practices (for example, not plugging in random flash drives). As much as possible, the application of security mechanisms should be "behind-the-scenes" so that the user does not have to consciously apply them.
    * Property 12: Mandatory Security Mechanisms. Encryption of sensitive data must be enforced to prove PCI DSS compliance.<sup>5</sup>
    * Property 14: Default Minimum Privilege. Users of the system will have the least privilege necessary to do their jobs effectively (with a default of read-only). The ability to access or modify the group server should be restricted to a very small number of employees who have been thoroughly screened to establish trust.
    * Property 15: Different Permissions for Different Groups. The many different types of users of the system should have different permission levels for the files which they are permitted to access. For example, users in many different departments may have read-only access to marketing or HR materials stored on the file server. Users may have both read and write access for some of the data belonging to their specific department.

<!-- Terry's Model-->
* <b>Model 3: File System for an Investigative Company with Sensitive Information</b>
  * The system will be deployed over a corporate network for a company/organization that deals with highly sensitive information (health records, criminal records, etc.).The File System will consist of many file servers and one group server on the corporate network. Most computers on the network will also have access to the Internet. However, the corporate network is not accessible outside of computers attached to the corporate network. Only computers with trusted MAC addresses installed are allowed into the network. Employees are expected to have gone through proper training and background checks, but low-level are not entirely trusted to be benign. It is assumed that it may be possible for a malicious low-level employee may be able to access the channels in the network, but not the file servers themselves. High-level employees with security clearance and seniority will be expected to be the managers of individual file servers to over-see and manage/oversee lower-level users in their server.
  * Trust Assumptions: It is assumed that the computers are installed with an up-to-date firewall and anti-virus software.It is also assumed that the computers on the network will run through a proxy server that will monitor and protect incoming and outgoing requests to the Internet, preventing unexpected access and data leakage.<sup>4</sup> Since the file system is deployed on a corporate network, we also trust that the uptime is long enough, that we do not need to worry about periodic back-ups.
  * Security Properties
    * Property 2: User Verification. - Users need some method to authenticate themselves, otherwise anyone could log on as anyone else.
    * Property 19: Group Owner. - Someone with high security clearance should be the administrator of individual groups, so that lower-level individuals cannot arbitrarily add others to groups with sensitive information. Also, the group owner should be able to kick malicious users without the consent of anyone else.
    * Property 4: File Consistency. - It's important that files stay up-to-date in this type of system.
    * Property 7: Data Confidentiality. - If someone manages to intercept data in travel, they should not be able to glean any information from that data. This is necessary because the data in travel will likely be highly secretive.
    * Property 8: Data Integrity. - It is important to detect malicious tampering of data. If sensitive information is altered (such as criminal background), it could lead to disastrous results.
    * Property 10: Transaction History. - It will be important to see who has accessed what files in case an investigation needs filed against an employee.
    * Property 11: Usability. - The user is a major liability, so keeping the interface as easy and simple to use will reduce accidental mess-ups.
    * Property 12: Mandatory Security Mechanisms. - Encryption of sensitive data must be enforced to prove PCI DSS compliance.<sup>5</sup>
    * Property 14: Default Minimum Privilege - It's important to have the default fail-safe so that a newly created user cannot access anything or do any harm to the files in the files system.
    * Property 15: Different Permissions for Different Groups. - A user should not be able to delete in a group they should not be able to just because they are able to delete in another group. i.e. a group owner should not have group owner privileges in another group (if they are not the owner of that group).
    * Property 16: Correct Token. - This ensures that permissions given are correct to each user and haven't been altered in any way while in travel to gain permissions a user should otherwise not have.
    * Property 17: Token Expiration. - Tokens must expire, because token caching is a huge liability. Either another user could use the same computer, or if someone steals the token from cache they would have the same permissions. To prevent the damage able to be done, tokens should only last for a finite amount of time.
    * Property 18: Token for Every Request. - Everything request should run through a mediator, so that there should be no way to access the files or file servers unless one has the pre-requisite permissions/token.


##Section 3: References
<!-- //TO-DO: Add references as you use them -->
<sup>1</sup>["Ten Things You Should Know About Tokens"](https://auth0.com/blog/ten-things-you-should-know-about-tokens-and-cookies/)<br />

<sup>2</sup>Jerome H. Saltzer and Michael D. Schroeder, "The Protection of Information in Computer Systems", *Proceedings of the IEEE* 63(9): 1278-1308, Sep. 1975.

<sup>3</sup>Adam Lee. Crypto History, Powerpoint. Sep. 6 2016

<sup>4</sup>["Why People Use Proxy Server and How to Use Proxy Server"](http://www.youngzsoft.net/ccproxy/use-proxy-server.htm)

<sup>5</sup>["Payment Card Industry Data Security Standard"] (https://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard), *Wikipedia*

<sup>6</sup>["Introduction to Certificates and SSL"] (http://docs.oracle.com/cd/E19830-01/819-4712/abloj/index.html), *Oracle Documentation*
