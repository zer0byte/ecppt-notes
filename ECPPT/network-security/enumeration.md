# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# Network Security
# Module 3 - Enumeration

https://cdn.members.elearnsecurity.com/ptp_v5/section_2/module_3/html/index.html

__________________________
## 3.1. Introduction
The goal of enumeration is to gather more detailed information on both devices and resources attached to the network. This includes account names, shares, misconfigured services and so on. Like the scanning phase, enumeration involves active connections to the remote devices in the network.

There are may protocols on networked systems that none can easily exploit if administrators do not take the necessary steps to either secure protocols or disable them.

For example, NetBIOS (Network Basic Input Output Systems) is the service that allows Windows systems to share files, folders, and printers among machines on a LAN. If not properly configured, it can lead to large amount of information leakage.

NetBIOS can be extremely useful in determining types of system information such as user IDs and open shares.

In addition to NetBIOS, a protocol that we will explore in this module is SNMP (Simple Network Management Protocol). It is a protocol used to both gather information and configure network devices (printers, switches, servers)

__________________________
## 3.2. NetBIOS
#### 3.2.1. What is NetBIOS
**History**
  The very first version of NetBIOS was developed late in 1983. It was designed as an API (not as a protocol as many suspect) that served its purpose in developing client/server applications.

  Since this old version was not intended to be encapsulated within TCP and UDP packets, in 1987 a new version was released: NetBIOS over TCP/IP (NetBT or NBT).

  This new version of NetBIOS, developed to work where the TCP/IP protocol suite is available, is considered a true protocol and it is described in the following two RFCs: [1001](https://tools.ietf.org/html/rfc1001) and [1002](https://tools.ietf.org/html/rfc1002)

**Purpose**
  The main purpose of NetBIOS is to allow applications on different systems to communicate with one another over the LAN. It is used for a multitude of purposes including: sharing printer and files, remote procedure calls, exchange messages and much more.
  As expected, these features may reveal additional information such as computer names, user names, domains, printers, available shares, and much more.

#### 3.2.2. How NetBIOS Works
PC's on a NetBIOS LAN communicate either by establishing a session (TCP) or by using datagrams (UDP). To do this, [NetBIOS](https://technet.microsoft.com/en-us/library/bb962072.aspx) uses the following TCP and UDP ports (see the illustration):
- UDP 137 for name services
- UDP 138 for datagram services
- TCP 139 for session services

1. Name services
  The name service has the same purpose of a DNS record, it translates and maps a NetBIOS name to an IP address.

  A name is an unique 16-byte address that identifies a NetBIOS resource on the network and is dynamically registered when either services or applications start. Names can be registered as unique names or as group names.

  You can find more information about NetBIOS name resolution [here][https://technet.microsoft.com/en-us/library/cc738412(v=ws.10).aspx].

  In order to locate a resource, a NetBIOS Name Query is used to resolve the NetBIOS name to an IP address. A name is composed of 16 characters: the firsts 15 characters can be specified by the user, while the 16th character is used to indicate the resource type and goes from 00 to FF (Hex).

  Name types available: [More](https://msdn.microsoft.com/en-us/library/cc224454.aspx)
  |       Name      |       Service/Type      |
  |-----------------|-------------------------|
  |[computer_name]00|Workstation Service      |
  |[computer_name]03|Messenger Service        |
  |[computer_name]06|RAS Server Service       |
  |[computer_name]1F|NetDDE Service           |
  |[computer_name]20|Server Service           |
  |[computer_name]21|RAS Client Service       |
  |[computer_name]BE|Network Monitor Agent    |
  |[computer_name]BF|Network Monitor App.     |
  |[user_name]03    |Messegner Service        |
  |[domain_name]1D  |Master Browser           |
  |[domain_name]1B  |Domain Master Browser    |
  |[domain_name]00  |Domain Name              |
  |[domain_name]1C  |Domain Control           |
  |[domain_name]1E  |Browser Service Elections|
  |__MSBROWSE__     |Master Browser           |

  You can run the following command to show the NetBIOS names on our machine:
  ```
  nbstat -n
  ```

  **The service that actually maps NetBIOS names to IP address is called Windows Internet Name Service (WINS).**
    If you want to dig deeper into WINS, here are some valid Microsoft resources:
    - [WINS Overview][https://technet.microsoft.com/en-us/library/cc725802.aspx]
    - [What is WINS][https://technet.microsoft.com/en-us/library/cc784180(v=ws.10).aspx]
    - [WINS defined][https://technet.microsoft.com/en-us/library/cc784707(v=ws.10).aspx]

2. Datagram services
  NetBIOS Datagram Service (NBDS) permits the sending of messages to a NetBIOS name. It runs on UDP port 138, therefore making it a connectionless communication.

  The datagram services allows the sending and receiving of the datagram messages to and from:
  - a specific NetBIOS name
  - broadcast the datagram to all NetBIOS names

  The datagram and broadcast methods allow one computer to communicate with several other computers at the same time however, these communications are limited in terms of message size. There is no error detection / correction using the datagram or broadcast method, however, datagram communication allows communications without the need for a session to be established.

3. Session services
  NetBIOS Session Service (NBSS) is the most commonly known of the NetBIOS services. It allows two names to establish connection in order to exchange data.

  For example, when a device creates a file sharing connection the session service is used. Once the session has been established, the two workstations use the Server Message Block (SMB) protocol, which we will explore later on.

  The following steps are used to establish the connection:
  1. The NetBIOS name is resolved into an IP address
  2. A TCP connection is established between the 2 devices, using TCP port 139
  3. The device starting the connection sends a NetBIOS Session Request over t he TCP connection
      1. This includes the NetBIOS name of the application that wants to establish the connection and the NetBIOS name to which to connect
  4. If the remote device is listening on that name, there will be a positive response and the response and the session will be established.

#### 3.2.3. SMB (Server Message Block)
Before seeing how to use NetBIOS, there is another popular protocol that we have to understand: Server Message Block. SMB lets you share files, disks, directories, printers, and in some cases, even COM ports across a network.

Before Windows 2000, SMB ran only with NetBIOS over TCP/IP (port 139), therefore a NetBIOS was required.

Windows 2000 and higher allow us to run [SMB directly over TCP/IP](https://support.microsoft.com/en-us/kb/204279) (direct hosting), without the need to run over NetBIOS sessions. To do this, the TCP port 445 is used.

Since SMB provides several features such as manipulating files, sharing, messaging, Interprocess Communication (IPC) and more, it is one of the most attractive service to explore during our enumeration phase.

#### 3.2.4. NetBIOS Commands and Tools
We will explore different commands and tools that can be used to enumerate system information using NetBIOS. The one we will use the most is the famous `nbstat`.

By using the data we gathered in the scanning phase, we can search for systems with ports 137/139/145 open.
###### 3.2.4.1 Nbstat
  [Nbstat](https://technet.microsoft.com/en-us/library/cc940106.aspx) is a tool developed to troubleshoot NetBIOS name resolution problems. The main options it offers are as follows:
  - `-a` (adapter status) : Lists the remote machine's name table given its name
  - `-A` (Adapter status) : List the remote machine's name table given its IP
  - `-c` (cache) : List NBT's cache of remote [machine] names and their IP addresses
  - `-n` (names) : List local NetBIOS names
  - `-r` (resolved) : Lists names resolved by broadcast via WINS
  - `-R` (Reload)   : Purges and reloads the remote cache name table
  - `-S` (Sessions) : Lists sessions table with the destination IP addresses
  - `-s` (session)  : Lists sessions table converting destination IP addresses to computer NetBIOS names
  - `-RR` (ReleaseRefresh) : Sends Name Release packets to WINS and starts Refresh

  Example:
    Let's suppose that, during our scanning phase, we came across a machine (192.168.99.162) that has the following open ports:
    ```
    Starting Nmap 6.49BETA5 ( https://nmap.org ) EST
    Nmap scan report for 192.168.99.162
    Host is up (0.085s latency).
    Not shown: 1990 closed ports
    PORT      STATE   SERVICE
    135/tcp   open    msrpc
    139/tcp   open    netbios-ssn
    445/tcp   open    microsoft-ds
    123/udp   open    ntp
    137/udp   open    netbios-ns
    ```

    Using this machine as target of our test, we can open a Windows terminal and use `nbstat -A` to start gathering information about it. Notice that on Windows systems, `nbstat` is already installed.

    The command will look like the following (see image):
    ```
    C:\>nbstat -A <target_IP_Address>

    Local Area Connection 2:
    Node IpAddressL [192.168.99.100] Score Id: []

        NetBIOS Remote Machine Name Table

        Name               Type       Status
    ---------------------------------------------    
    ELS-WINXP      <20>   UNIQUE    Registered
    WORKGROUP      <20>   GROUP     Registered
    ELS-WINXP      <20>   UNIQUE    Registered
    WORKGROUP      <1E>   GROUP     Registered
    WORKGROUP      <1D>   UNIQUE    Registered
    ..__MSBROWSE__.<01>   GROUP     Registered

    MAC Address = 00-50-56-B1-94-80
    ```

    From here we can see that the computer name is *ELS-WINXP* and that the domain name is *WORKGROUP*.
    The `20` in `ELS-WINXP <20> UNIQUE Registered` refers to a server service (from the table earlier (approx. line 49)). This means that the host has file and printer shares enabled, therefore we may be able to access them.


###### 3.2.4.2. Nbtscan
  In Linux, there are other tools that allows us to obtain similar information. One of the most popular is `nbtscan`. The most basic command to run is the following:
  ```
  nbtscan -v [target_IP_Address]
  ```
  or for several network:
  ```
  nbtscan -v [target_IP_Address]/[subnetmask]
  ```

  The tools we have seen up to this point operate using the NetBIOS Naming Service (NBNS).

###### 3.2.4.3. Net command
  With this information we can now move on  and verify what the target machine is sharing over the network. To do so we can use the Microsoft [net][https://technet.microsoft.com/en-us/library/bb490949.aspx] command. The `net` command offers many features such as the ability to update user accounts, display, view, and modify services, connect computers to shared resources and much more.

  For our purposes, we will only focus on the [net view][https://technet.microsoft.com/en-us/library/hh875576.aspx] command.

  `Net view` allows us to list domain, computers, and resources shared by a computer in the network. Let us see how to use it against our previous target.
  The command we are going to run is the following:
    ```
    C:\>net view 192.168.99.162
    Shared resources at 192.168.99.162

    Share name    Type   Used as    Comment
    ---------------------------------------------------
    C             Disk
    Frank         Disk
    FrankDocs     Disk
    My Documents  Disk
    WorkSharing   Disk

    The command completed successfully.
    ```

  To explore these shares we can simply browse them by utilizing the [net use](https://technet.microsoft.com/en-us/library/bb490717.aspx) command.

  The `net use` command can be used to connect or disconnect a computer from a shared resource. This means that we can connect our computer to the remote shred folder in order to navigate the remote folders.

  For example, if we want to start a connection on the C resource, we can use the following command:
  ```
  net use K: \\192.168.99.162\C
  ```

  The command will add the `K:` drive to our mapped drives, thus containing the files and folders from the victim `C` resource. We can now explore these files or attach other shares to see if the machine exposed useful information.

###### 3.2.4.4. Smbclient and mount
  If you are using a Linux machine, the same results can be obtained with different tools. If we want to list all the shares of a specific computer we can use `smbclient` as follows:
  ```
  $ sudo smbclient -L 192.168.99.162
  Enter root's password:
  Domain=[ELS-WINXP] OS=[Windows 5.1] Server=[Windows 2000 LAN Manager]

        Sharename       Type     Comment
        ---------       ----     -------
        My Documents    Disk
        IPC$            IPC      Remote IPC
        Frank           Disk
        C               Disk
        WorkSharing     Disk
        FrankDocs       Disk
        ADMIN$          Disk     Remote Admin
        C$              Disk     Default Share
  Domain=[ELS-WINXP] OS=[Windows 5.1] Server=[Windows 2000 LAN Manager]
  ```

  As you can see, `smbclient` also displays a few other hidden shares such as `IPC$`, `C$` and `ADMIN$`. You can identify hidden shares since they have a `$` sign at the end.

  The three shares listed above are the default administrative shared and have their own specific purpose. For example `IPC$` is used for *Inter-process communications* and can be used to leverage *null* session attacks.

  If we wish to navigate the target shares, we can use mount as an alternative to `net use`. For example, if we want to navigate the C share, we will run something similar to the following command.
  ```
  sudo mount.cifd //192.168.99.162/C /media/K_share/ user=,pass=
  ```

  After we run it, we will be able t o browse the remote share (see image - shows we can `ls` into it).

#### 3.2.5. Null Session
We have seen this far some examples of basic NetBIOS information that we can gather from Windows and Linux OS.

Now we will move on to other tools and commands that can also provide a great deal of additional information. We will also query the NetBIOS API and exploit null sessions.

Null sessions are one of the oldest and most known attacks performed on Windows 2000 and Windows NT environments. Thanks to this weakness, malicious users are able to establish a connection to the victim in order to gather information such as shares, users, groups, registry keys, and much more.

Null session rely on Common Internet File System (CIFS) and Server Message Block (SMB) API, that return information even to an unauthenticated user.

In other words, a malicious user can establish a connection to a Windows system without providing any username or password. In order for the attack to work, the connection must be established to the administrative share named IPC (Inter Process Communication).

The easiest way to test if a machine is vulnerable to null session is running the `net` command. Note that in contrast to the connection we established in the previous slides, we are going to target the `IPC$` share instead:
  ```
  C:\> net use \\192.168.99.162\IPC$ "" /u:""
  The command completed successfully.
  ```

  Description:
  - `IPC$` : is the hidden share that we are trying to connect to
  - `192.168.99.168` : IP address
  - `""` : null password
  - `/u:""` : empty (anonymous) username

As we can see in the screenshot, the command works. From this moment on, we have an active connection to our victim. Then, we can gather the information from it.

There are some tools that are specifically designed to exploit null session. With these tools we will be able to automatically gather a great deal of information from the remote machine.

Notice hat some of these tools are very old and OS dependent, therefore, we will use both Windows or Linux.

###### 3.2.5.1. Winfingerprint
  Wingerprint is an administrative network resource scanner that allows us to scan machines in our LAN in order to gather details about each host. This includes NetBIOS shares, disk information, services, users, groups, and more.

  By selecting the boxes in its GUI, we are able to enumerate information such as user SID, password policy, users, shares, and much more.

###### 3.2.5.2. Winfo
  Winfo is another simple enumeration tool for NetBIOS as it displays all the information through null sessions. In contrast with the previous tool, it does not offer a graphical interface. Instead, we will have to run it from our command prompt.

  The command to execute it is very simple:
  ```
  winfo <taget_IP_Address> -n
  ```

  Where `-n` tells the tools to establish a null session before trying to dump the information.

  The following snippet shows the `winfo` results:
  ```
  Null session established.
  USER ACCOUNTS:
  * Administrator
    (This account is the built-in administrator account)
  * eLS
  * Frank
  * Guest
    (This account is the built-in gurst account)
  * netadmin
  * SUPPORT_388945a0
  SHARES:
  * My Documents
  * IPC$
  * Frank
  ...
  ```

###### 3.2.5.3. DumpSec


__________________________
## 3.3. SNMP


__________________________
