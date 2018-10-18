# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# Network Security
# Module 4 - Sniffing and MitM Attacks

https://cdn.members.elearnsecurity.com/ptp_v5/section_2/module_4/html/index.html

__________________________
###### Module Map
1. What is Sniffing
2. Sniffing in Action
3. Basic of ARP
4. Sniffing Tools
5. Man in the Middle Attacks
6. Attacking Tools
7. Intercepting SSL Traffic

__________________________
## 4.1. What is Sniffing
Network eavesdropping or network sniffing, is a network layer attack consisting of capturing packets transmitted by other computers.

  Having these packets will not only allows us to read the data, but also search for sensitive information like passwords, session tokens, or various types of confidential information.

  In sniffing, sometimes we have to mount Man-in-the-Middle (MitM) attacks to achieve our goals.

#### 4.1.1. MitM, Hubs, and Switches
A MitM is an attack where the malicious user is able to intercept communications between 2 systems.
  For example, in an HTTP transaction, the target is the TCP connection between client and server.

  In a MitM attack scenario, the attacker can split the original TCP connection into 2 new connections, one between the victim and the attacker and the other between the attacker and the destination.

  Once the TCP connection is intercepted, the attacker acts as a proxy, being able to read, insert, and modify the data in the intercepted connection.

#### 4.1.2. Hubs and Switches
Until the early 90's all the Ethernet networks used Hubs to build meshed network topology. Hubs are layer 1 device that do not deal with packets, but just with bits. Hubs are repeaters, they receive electric signals on the port and repeat the same signal on all other ports.

  In such environments, packets meant for one machine are received by all the other machines. Every time a packet arriving at a NIC does not have that NIC's MAC in the destination field of the Layer 2 frame, the packet is dropped.

  NIC drivers were developed to let NICs still accept and handle those packets. This NIC behavior was called *promiscuous mode* and it is still available today on most NICs in the market.

When switches were introduced, they gradually replaced hubs. Switches are layer 2 devices (sophisticated ones includes layer 3) capable of dealing with frames instead of just electric signals. They have a certain level of logic that allows them to handle addresses and forwarding rules.

  To make thing clearer, the main difference between hubs and switch is the forwarding mechanism: switches are capable of forwarding frames only to the real destination or at least forward the packet on the port on which the destination is registered.

  Hub instead just propagate the electric signal received from one port to all the others. They are physical layer devices.

With the introduction of switches, sniffing became more difficult. In a normal and not stressed switched network sniffing for data is impossible.
Efficient attack techniques have been introduced to force switches to behave like a hub and then forward frames on all the ports.

__________________________
## 4.2. Sniffing in Action
Types of Sniffing:
1. Passive Sniffing
2. Active Sniffing
  - MAC Flooding
  - ARP Poisoning

#### 4.2.1. Passive Sniffing
Passive sniffing attacks are performed by just *watching* packets on a network in order to gather sensitive information such as *userids*, *passwords*, and other sensitive information.

They are difficult to be detected due to their "hands off" approach to gathering information.

The only tool you need is a sniffer, such as Wireshark.

#### 4.2.2. Active Sniffing
Active sniffing is performed by actively (malicious) operations (MAC flooding or ARP poisoning) on the network. This means that we will inject packets on the network in order to redirect the traffic.

Types of Active Sniffing:
1. MAC Flooding
  MAC flooding is meant to stress the switch and fill its CAM table. A CAM table keeps all the info required to forward frames to the correct port: `<MAC address-port number-TTL>`.

  When the space in the CAM is filled with fake MAC addresses, the switch cannot learn new MAC addresses.
  The only way to keep the network alive is to forward the frames meant to be delivered to the unknown MAC address on all the ports of the switch, thus making it fail open, or act like a Hub.

2. ARP Poisoning
  ARP poisoning (a.k.a. ARP spoofing) is probably the most stealthy among the Active sniffing techniques.
  It does not need to bring down switch functionalities, instead it exploits the concept of traffic redirection.
  This is one of the most used attacks to perform Man in the Middle Attacks.

  By exploiting the network via ARP poisoning, the attacker is able to redirect the traffic of the selected victims to a specific machine (usually the attackers machine). Doing this will enable the attacker to not only monitor, but also modify the traffic.

  Notice that although ARP poisoning is mainly used to mount a MitM attack, it can also be used to DoS the network.
__________________________
## 4.3. Basic of ARP
  [ARP](https://tools.ietf.org/html/rfc826) stands for Address Resolution Protocol and it is available and supported by all NICs and OS.

  ARP has been developed to be a quick way to match Layer 3 network addresses (IP address) with Layer 2 addresses (MAC addresses).

  The ARP protocol recognizes 2 types of ARP packets : ARP requests and ARP replies.

  ARP works in conjunction with an ARP table, which stores the IP-MAC pairs and a time to live value related to each entry.

  Each node maintains its own table (IP-MAC). Of you want to check your ARP table you can use the following command:
    ```
    C:\Users\els>arp -a

    Interface: 192.168.102.149 ---0xb
      Internet Address        Physical Address      Type
      192.168.102.2           00-50-56-ef-66-cf     dynamic
      192.168.102.255         ff-ff-ff-ff-ff-ff     static
      255.255.255.255         ff-ff-ff-ff-ff-ff     static

    stduser@els:~$ arp
    Address             HWtype   HWaddress            Flags   Mask  Iface
    192.168.102.2       ether    00:50:56:ef:66:cf    C             eth0
    192.168.102.254     ether    00:50:56:e1:65:94    C             eth0
    ```

  The following example will shed some light on ARP tables:
    When host *A* creates a packet destined to host B, before it is delivered to its destination (*B*), *A* searches into its ARP table.

    - If the *B*'s layer 3 address is found in the table (meaning the IP_B), the correspondent MAC address (MAC_B) is inserted as the Layer 2 destination address into the protocol frame.

    - If the entry is not found (You can view this processes using Wireshark)<br>
     1. An ARP request is sent on the LAN <br>
       The request contains the following values in the destination fields of the IP-Ethernet packets:
        - Source IP Address: IP_A
        - Source MAC Address: MAC_A
        - Destination IP Address: IP_B
        - Destination MAC Address: FF:FF:FF:FF:FF:FF (this indicates a broadcast message)

        The 48 bit MAC Address used as the destination is the Layer 2 broadcast address:
        the ARP Request reaches all the nodes in the broadcast domain.

        The nodes whose IP address does not match with the destination IP_B will just drop the packet.

      2. The nodes whose IP address matches IP_B, will respond with an ARP Reply to the sender
        This is the information that the reply will contain:
          - Destination MAC : MAC_A
          - Destination IP address : IP_A
          - Source IP address : IP_B
          - Source MAC : MAC_B

        At this point host A has the information it was looking for: MAC_B

        It can add this information to the frame and forward the message to the correct node. It will also be inserted in its MAC table for later use.

  The following list summarizes when ARP is used:
   - A host desires to send a packet to another host in the same network
   - A host desires to reach another host beyond his local network and needs the gateway hardware address
   - A router needs to forward a packet for one host through another router
   - A router needs to forward a packet to the destination host on the same network

#### 4.3.1. Gratuitous ARP
This is how ARP works if one of the host in the network asks for it.
For our attacking purposes it is also very important to know that this is not the only way.
The so-called gratuitous ARP requests and responses are also possible:
- Gratuitous ARP request <br>
  it is a request packet where source and destination IP are set with the IP of the machine that is issuing the packet and the destination MAC is the broadcast address
- Gratuitous ARP reply <br>
  it is an ARP reply that has been sent without being requested

Although they may be useful to detect IP conflict or simply inform other hosts/switches of a MAC address in the network, attacker can use these packets to mount ARP poisoning attacks

#### 4.3.2. ARP Poisoning
ARP poisoning is performed by poisoning the cache of other hosts in the network. We have 2 main ways to mount this type of attack:
- Host Poisoning
  In the first scenario, the attacker will create a Man-in-the-Middle configuration between 2 hosts, transferring data between them.

  PC *M* (attacker) would forge Gratuitous ARP reply packets and send them to both the communication peers.

  All the traffic from B to A and from A to B will pass through M. M must be able to forward the packets quickly to keep the system administrator from suspecting anything.

- Gateway Poisoning
  The second scenario is one-way:<br>
  The machine that is going to sniff traffic in the network will send *Gratuitous ARP Replys* to some or all the hosts in a network, announcing his MAC address as the MAC address of the default gateway of the network.

  Once again, this is achieved by forging an ARP Reply containing a fake IP to MAC correspondence.

  With this kind of redirection *M* (attacker) can get all the data with a foreign destination address and pass it to the real gateway. *M* should be able to process a big amount of packets each second.

  Unintentional DoS can occur in the network if *M* is too slow forwarding the packets.

  Now that we have a good overview of how an attacker can mount an ARP poisoning attack, let us see which tools we can use to intercept and analyze network traffic.

__________________________
## 4.4. Sniffing Tools
#### 4.4.1. [Dsniff](http://www.monkey.org/~dugsong/dsniff/)
  The dsniff suite has a collection of tools for active/passive sniffing, MitM attacks, and can also monitor the network for data such as passwords, emails, files, and much more.

  It is important to understand that dsniff is no longer being actively developed and there will be no further enhancements.

  Besides dsniff itself, which is able to capture plaintext passwords on a network, the package also contains the following tools:
  - Passive
    - Filesnarf
    - Mailsnarf
    - Msgsnard
    - Urlsnarf
    - Webspy
  - Active
    - Arpspoof
    - Dnsspoof
    - Macof
  - MitM
    - Sshmitm
    - Webmitm

  Dsniff itself is a password sniffer which handles FTP, Telnet, SMTP, HTTP, POP, popass, NNTP, IMAP, SNMP, LDAP, Rlogin, RIP, OSPF, PPTP MS-CHAP, NFS, VRRP, YP/NIS, SOCKS, X11, CVS, IRC, AIM, ICQ, Napster, PostgreSQL, Meeting Maker, Citrix ICA, Symantec pcAnywhere, and many more.

  In this section we will focus on passive tools.

###### 4.4.1.1. Dniff
  The command structure for dsniff is the following:
    ```
    dsniff <options>
    ```
  where options include:
    - `-c` Perform half-duplex TCP stream reassembly, to handle asymmetrically routed traffic (such as when using arpspoof to intercept client traffic bound for the local gateway)
    - `-d` Enable debugging mode
    - `-m` Enable automatic protocol detection
    - `-n` Do not resolve IP addresses to hostnames
    - `-p` Process the contents of the given PCAP capture file
    - `-i` Specify the interface to listen on

  As you can see from the options listed, dsniff is not only able to capture and save the authentications it sees on the wire, it is also able to analyze files in order to get the same information.

  In other words, you can feed dsniff with a pcap (packet capture) file from Wireshark and let it analyze the traffic.

  Example:
    In our example we run dsniff with root privileges. It will automaticaly attach itself to our main interface: *eth0*.
    Once the user logs in, dsniff lists the following as output.
    ```
    stduser@els:~$ sudo dsniff
    dsniff: listening on eth0
    -----------------
    12/30/15 04:32:21 tcp 192.168.1.6.43709 -> 192.168.1.1.60 (http)
    GET /login.cgi?username=admin&password=password HTTP/1.1
    Host: 192.168.1.1

    -----------------
    12/30/15 04:33:23 tcp 192.168.1.6.43713 -> 192.168.1.1.60 (http)
    GET /login.cgi?username=admin&password=password HTTP/1.1
    Host: 192.168.1.1

    -----------------

    ```

  Although dsniff is a valid tool, if we want to inspect deeper the traffic and the credentials sent in the network, there are more powerful tools that we can use.


#### 4.4.2. Wireshark
Steps on working with Wireshark:
1. Select Interface
  First we start Wireshark and select the interface to use for the sniffing. Be sure to select the correct interface. In case you are attached to the network via Wi-Fi, you will probably use the wireless LAN interface *wlan0*.

  Then, since in our test we are looking at a web application, we will set the capture filter to only watch HTTP traffic.

2. Pick a Log File
  In addition to the previous settings, we also want to save our results to a file called **eth0_packet_configure_http**.
  Notice that all these options can be configured by clicking on the *capture option* button.

3. Start the Capture
  Notice that with the filter selected, we will see every packet sent and received to and from port 80 (HTTP). If we want to display only HTTP traffic, we can add the word **http** in the expression field.

4. Filter Packets
  Depending on the authentication mechanism implemented on the target web application, we will have to apply specific filters in order to get only the meaningful packets.

    For example, if the application implements a basic HTTP authentication mechanism, we can use the **http.authbasic** filter, which will list all the packets containing credentials sent to the application.

    We can apply filters in 2 different ways:
    1. Write the filter in the filter field
    2. Click on Expression and Select **HTTP -> http.authasic - Credentials**

5. Study Packets
  We can inspect the packet in the bottom panel of Wireshark, or we can right click on the packet and select **Show Packet in a New Window**.

  Then, look for the major heading named **Hypertext Transfer Protocol**

  Once there we have to open the child node named **Authorization: Basic <string>**, and look for the **Credentials** line. Here we can find the credentials used for the authentication.

#### 4.4.3. [TCP Dump](http://www.tcpdump.org/)[Manual](http://www.tcpdump.org/manpages/tcpdump.1.html)
  tcpdump is a powerful packet sniffer that runs via command line.
  It allows the user to intercept and display and display TCP/IP and other packets being transmitted or received over a network, to which the computer is attached.

  Much like Wireshark, tcpdump has the ability to filter the traffic and save the packets to a file for later analysis.

  We will now cover some basic capabilities

  Basic syntax:
    ```
    tcpdump [options] [filterexpression]
    ```

  In our example, we want to see all traffic on our main network interface (eth0), so we will use the following command:
    ```
    sudo tcp dump -i eth0
    ```

    This states that we want to run tcpdump as root and monitor the eth0 network interface. Since no other options have been added, we will see all packets transmitted.
      ```
      stduser@els:~$ sudo tcpdump -i eth0
      [sudo] password for stduser:
      tcpdump: verbose input surpressed, use -v or -vv for full protocol decode
      listening on rth0, link-type EN10B (Ethernet), capture size 262144 bytes
      09:18:02.133182 IP 192.68.103.1.17500 > 192.168.102.255.17500: UDP, length 200
      09:18:02.854919 IP 192.68.103.147.56976 > 192.168.102.2.domain: 53964+ 255.102.168.192.in+addr.arpa. (46)
      09:18:02.864964 IP 192.68.103.2.domain > 192.168.102.147.56976: 53964 NXDOMAIN 0/0/0 (46)
      09:18:02.865051 IP 192.68.103.147.59910 > 192.168.102.2.domain: 12279+ PTR? 1.102.168.192.in-addr.arpa. (44)
      09:18:02.875296 IP 192.68.103.2.domain > 192.168.102.147.59910: 12279 NXDomain 0/0/0 (44)
      09:18:03.848147 IP 192.68.103.147.48873 > 192.168.102.2.domain: 27140+ PTR? 2.102.168.192.in.addr.arpa. (44)
      09:18:03.858098 IP 192.68.103.2.domain > 192.168.102.147.48873: 27140  NXDomain 0/0/0 (44)
      09:18:03.858183 IP 192.68.103.147.50818 > 192.168.102.2.domain: 50563+ PTR? 147.102.168.192.in-addr.arpa. (46)
      09:18:03.867137 IP 192.68.103.2.17500 > 192.168.102.147.50818: 50563 NXDomain 0/0/0 (44)
      ```

    We can inspect in more detail by using adding parameters to our previous command:
      ```
      -xxAXXSs 0 dst 192.168.102.139
      ```

    Description (see image for example):
    - `-s 0` we set the MTU size to 0, in order to get the entire packet
    -  `-dst` Shows only the communications with the destination specified
    -  `-A` Print each packet (minus its link level header) in ACII
    -  `-XX` When parsing and printing, in addition to printing the headers of each packet, print the data of each packet including its link level header, in hex
    -  `-xx` When parsing and printing, in addition to printing the headers of each packet, print the data of each packet, including its link level header, in hex
    -  `-S` Print absolute, rather than relative, TCP sequence numbers
    -  `-s` Snaf snaplen, bytes of data from each packet rather than the default of 68 <br>
        68 bytes is adequate for IP, ICMP, TCP, and UDP but may truncate protocol information from name server and NFS packets (see below). Packets truncated because of a limited snapshot are indicated in the output with **[|proto]**, where is the name of the protocol level at which the truncation has occurred. Note that taking larger snapshots both increases the amount of time it takes to process packets and effectively decreases the amount of packet buffering. This may cause packets to be lost. Setting snaplen to 0 means to use the required length to catch whole packets.

    From the output we can see that only the traffic aimed to the host **192.168.102.139** is displayed. Indeed, we can see part of the way handshake (SYN and ACK) and then the packet containing the data sent to the server.

    We can also see that the traffic is sent to a webserver, indeed the destination address and port are displayed as follows:
    ```
    09:57:32.763851 IP 192.168.102.147.43357 > 192.168.102.139.http: Flags [S],
    seq 661243647, win 29200, options [mss 1460, sackOK,TS val 6706799 ecr 0, nop, wscale 7], length 0
            0x0000: 000c 2978 6331 000c 29d3 f371 0800 4500 ..)xc..)..q..E.
    ```

    The previous output may contain a lot of information. If we want a simpler output, we can just remove some of the parameters, and run the following command (see image):<br>
      ```
      sudo tcpdump -i eth0 -vvvASs 0 dst 192.168.102.139
      ```

      Here we removed all the hexadecimal output but we increased the output verbosity with the `-vvv` argument.

    As you can see in the output, the data contains the same **Authorization** header seen before with Wireshark.

      The only difference is that Wireshark automatically decodes the base64 encoded text for us. So, when using tcpdump, we will have to decode the information manually.

      There are different tools and web applications that we can use to do that. We can use BurpSuite, the web browser console, command line, or online tools such as [bsae64decode](https://www.base64decode.org/).

  If you are running on a Windows machine, you can use [Windup](https://www.winpcap.org/windump/).

__________________________
## 4.5. Man in the Middle Attacks
#### 4.5.1. What they are
As you already know, MitM is an attack in which the attacker is able to read, modify, or insert arbitrary data in packets transmitted between 2 peers.

The most simple scenario of a MitM attack can be described as follows:
  The attacker is able to gather the packets sent from the legitimate source of data transfer; these packets would then be redirected unmodified to the legitimate destination peer, which will not be able to understand the path the packet had followed.

MitM is an advanced technique and requires some prerequisites for the attack to be successful. The most common use of this attack is in LAN due to lac of security in Layer 2-3 protocols such as ARP and DHCP.

Let us see the attacks in details.

#### 4.5.2. ARP Poisoning for MitM
ARP poisoning can be exploited to add fake information between 2 communication peers into a local network.
In a scenario in which M (the attacker) wants to listen to all the traffic between A and B, M would have to send fake IP-MAC pairs to both A (server) and B (client), making himself the Man in the Middle.

The following are the steps for a successful attack:
  1. M would pretend to be B to A: it will send a gratuitous ARP reply with the pair: **IP_B->MAC_M**
  2. M would pretend to be A to B: it will send a gratuitous ARP reply with the pair: **IP_A->MAC_M**

  Because of the TTL in hosts ARP caches, an attacker would need to send these packets at interval lower than the timeout (usually every 30 seconds is a good choice).

  Once the gratuitous ARP packet is sent, B's ARP cache gets poisoned with the entry: **IP_A->MAC_M**

  Next time B wants to send a packet to A, it will be forwarded to M.

This attack leaves the MAC address of the attacker in the ARP cache of the victims.

Another gratuitous ARP with correct values would restore the correct values after the sniffing is completed.

Countermeasures:
  Using static ARP is not a feasible approach into a large and always changing networks. Tools like *arpwatch* or *arpcop* can detect but not stop such attacks.


#### 4.5.3. Local to Remote MitmM
When a host in a LAN wants to send packets to hosts outside the LAN it uses the default gateway.
Default gateway MAC address must be used to forward the packet along with the correct IP address configured by administrator or given by DHCP.

The use of ARP poisoning in this scenario leads to a MitM attack from local to remote.

(See the diagram) Host A sends all the traffic aimed for the internet through the Attacker.

The following describes the steps that take place in the previous scenario:
1. Host A wants to send packets to the internet. It already has the IP of the gateway (IP_G) and it needs the associated MAC address.
2. M can use a gratuitous ARP reply to advertise itself as the default gateway: binds IP_G with his own (MAC_M)
3. All the traffic meant to leave the LAN will pass through M, which will then redirect it to the real gateway

#### 4.5.4. DHCP Spoofing
DHCP is a service usually running on routers to dynamically assign or revoke IP address to new hosts on the network.
  The protocol is based on the UDP protocol and consists of an exchange of messages that are mostly sent in broadcast and are visible to the entire broadcast domain.

  A host trying to enter the network asks for an IP. It will pick the best offer and use that IP address from that point on.

It is important to know hat if the whole communication succeeded, the DHCP server will also set the client default gateway. Due to its implementation, an attacker can spoof the DHCP messages in order to mount a MitM attack.

Before inspecting any further, let us see how DHCP works.
The exchange of messages will be ass follows:
  1. A new host is connected to the network: it send a DHCP Discovery broadcast packet using UDP on port 67 <br>
  Since the host still needs an IP to be assigned, the source address of the packet is 0.0.0.0.

  2. The DHCP server in the same broadcast domain responds with a DHCP offer packet composed as follows

    |YIADDR    | 10.1.1.34         |
    |----------|-------------------|
    |Lease Time| 3600              |
    |SRC IP    | 10.1.1.1          |
    |DST IP    | 255.255.255.255   |
    |MAC SRC   | Router_MAC        |
    |MAC DST   | FF:FF:FF:FF:FF:FF |

    Description:
    - YIADDR : Your IP Address (Being offered by router)
    - DST IP : Destination IP Address, which is still broadcast
    - Lease Time (in second) : defines the validity period of the offered IP

  3. The client responds with another broadcast packet: DHCP REQUEST <br>
    The destination address is still broadcast since more than one DHCP server may have sent another DHCPOFFER.

    The client uses 0.0.0.0 since it has not received a verification from the server

    DHCP clients choose the best offer according to the lease time attribute in the DHCP offer: the longer the better. The packet is used to designate a winner between all the DHCP servers.

  4. The DHCP server that recognizes that itself as the winner sends a DHCPACK packet in broadcast. The YIADDR contains the client IP address while the CHADDR (Client Ethernet Address) contains the client MAC address.


All packets seen so far are sent in broadcast, thus everyone in the network receives the DHCP packets, even those hosts not involved in the communication.

What happens if we are in the same broadcast domain and we act as rogue DHCP server?

What we have to do is send our DHCPOFFER with a greater lease time. This lure the victim to choose our offer and then set configurations we will send.

As you already know, DHCP Servers not only offer IP addresses but they can also provide a default gateway for the network. By competing with legit DHCP servers (and winning by increasing the lease time), we can set ourselves as the default gateway.

In this way all the traffic leaving the network from the client host will reach our machine (attacker) and then the real gateway.

#### 4.5.5. MitM in Public Key Exchange
The following topic will be a bit theoretical, but contain great examples of what MitM attacks can accomplish.

We will see how a man in the middle attack can be mounted to hijack the delivery of a public key into an asymmetric key encryption communication.

Notice that this affects only the key exchange and not the authentication mechanism that may be implemented to defeat MitM, unless you are able to fake root CA's signatures.

This is something that [Sotirov](http://www.win.tue.nl/hashclash/rogue-ca/) did through the MD5 collisions in 2009.

First, you should be aware that asymmetric encryption is based on the encryption/decryption through 2 different keys.

One is the private key and must be kept absolutely confidential. The other is the Public key and can be given to a Key distribution center that will make it available to anyone.

If Alice wants a confidential conversation with Bob, she needs Bob's Public key.

If Bob has not given Alice the key, there is no other way to start a confidential conversation than getting the public key from a key distribution server or from Bob himself through the internet.

The steps Alice must take are:
1. Alice queries the Key server for Bob's public key
2. The Key Server returns Bob's public key to Alice
3. Alice encrypts her message using Bob's public key and sends the message to Bob

In the previous scenario, the MitM must be able to sniff traffic on Alice's network or on the Key Server network (through ARP poisoning or DHCP snooping, etc).

Of course it is far easier that this attack to be performed on Alice's network, since Key Servers have enhanced security measures.

In order for the attack to work, the Attacker (M) should be able to recognize the queries to the Key Server and take following steps to mount a successful MitM attack.

  The MitM (attacker) should:
  1. Intercept Alice's query and forward it to the Keys server
  2. Intercept Bob's public key and store it for further use
  3. Send his own Public key to Alice instead of Bob's public key
  4. Alice would encrypt data using M's Public key thinking that she is using Bob's key
  5. MitM would intercept Alice's encrypted messages, decrypting them with his private key and them forward them to Bob using Bob's public key saved at step 2)

#### 4.5.6. LLMNR and NBT-NS Spoofing/Poisoning
[LLMNR](https://en.wikipedia.org/wiki/Link-Local_Multicast_Name_Resolution) (Link-Local Multicast Name Resolution) and [NBT-NS](https://technet.microsoft.com/en-us/library/cc958811.aspx) (NetBIOS Name Service) spoofing are also 2 very effective methods for capturing user's NTLMv1, NTLMv2, or LM (LAN Manager) hashes, through a MitM attack.

LLMNR is the successor of the NBT-NS, and was introduced into the Windows ecosystem starting with Windows Vista.

Both LLMNR and NBT-NS allow for machines within Windows-based network to find one another and is essentially a "fall-back" protocol used for the resolution of hostnames within a network when resolving of hostnames via DNS fails.

This process of hosts reverting to LLMNR or NBT-NS broadcast for host discovery results in NTLMv1/v2 hashes being sent over the network offering an attacker on the same network segment the opportunity to intercept, and replay the hashes to other systems, or alternatively, crack the intercepted hashes offline.

A typical scenario of attacking LLMNR or NBT-NS broadcast is as follows (see diagram):
  1. Host A request an SMB share at the system `\\intranet\files`, but instead of typing `intranet`, misatakenly types `intrnet`
  2. Since `intrnet` can't be resolved by DNS as it is an unknown host, Host A then falls back to sending an LLMNR or NBT-NS broadcast message asking the LAN for the IP address for host `intrnet`
  3. An attacker (Host B), responds to this broadcast message caliming to be the `intrnet` system
  4. Host A complies and sends Host B (the attacker) their username and NTLMv1 and v2 hash to the attacker

#### 4.5.6.1. Responder/Multirelay
  [Responder](https://github.com/lgandx/Responder) is an excellent tool we can utilize for exploiting the LLMNT and NBT-NS weakness for capturing NTLMv1/v2 hashes and relaying them for authentication to other systems.

  Responder works by listening for LLMNR or NBT-NS braodcast messages and spoofing responses to targeted hosts, resulting in intercepting hashes we can either pass (relay) to other systems, or crack offline.

  We can use it conjunction with its "[MultiRelay](https://github.com/lgandx/Responder/blob/master/tools/MultiRelay.py)" tool, which will be responsible for relaying the hashes to other machines on the LAN, and can provide us with MultiRelay shell if successful.

  Important:
    It should be noted that one of the pre-requisites for this attack is that "SMB Signing" has been disabled on the workstations. For determining whether ornnot SMB Signing is enabled on a target, we can use RUnFinger.py tool which is also included with the Responder toolkit.

    We simply specify the `-i` switch and our target:
      ```
      $ python RunFinger.py -i <target_IP>
      ```
  The steps for launching this attack are generally as follows:
    1. Modify the Responder.conf configuration file and disable the "SMB" server and "HTTP" server options by setting the values to "Off"
    2. Launch Responder.py with `-i` (interface) and additionally, using the `-lm` option can help with downgrading NTLMv1 or v2 to LM hashes where supported:
      ```
      $ python Responder.py -I eth0 --lm
      ```
    Responder should begin responding to LLMNR and NBT-NS requests at this point.

    3. In another window, we launch the "MultiRelay.py" tool, found within the "tools" directory of the Responder package. We specify a target name with the `-t` switch, and we can use "ALL" value for the user switch with `-u`:
      ```
      $ python MultiRelay.py -t <target_IP> -u ALL
      ```

    A successful hash relay will result a MultiRelay "shell". From this hell we can use a number of its built-in options, or execute our own commands for furhtering our foothold.

__________________________
## 4.6. Attacking Tools
#### 4.6.1. Ethercap: Sniffing and MitM Attack
Ethercap is an open source program that combines a packet sniffer for different protocols (POP/HTTP/HTTPS/SFTP), but it also offers password cracking features.

Steps:
1. In order to start Ettercap, let us run the following command in out terminal:<br>
  ```
  sudo ettercap -G
  ```
  The `-G` options instructs Ettercap to use GTK+ GUI, in other words, it instructs Ettercap to start the graphical interface.

2. Select the interface to use and the sniffing option <br>
  We can choose between:
  - Unified : it sniffs all the packets on the cable
  - Bridged : it uses 2 network interfaces and forwards the traffic one to the other

3. Once we select the sniffing option (unified in our case), a new window appears <br>
  Here we have to select the interface to use.
  In our case we will select the `tap0` interface and click `OK`.
  Once we confirm, the options and the interface will change.

4. Right now Ettercap is sniffing the traffic on the network. You can see the connection intercepted by clicking on `View` and then select `Connections`

5. The first step once we run Ettercap is to scan the network in order to find alive hosts

  This is the easiest step, but may take a while depending on how your network is set up. To do this let us click on `Hosts` and then `Scan for hosts`.

  It will go through its automatic scanning steps while showing you its progress.

6. Once it is done, we can see the results by clicking on `Host list` in the `Host` menu

From here we can select which of these hosts will be the targets of our attack. We just need to select them and then click on `Add target 1` and `Add target 2`

  While you can pick as many hosts as you like, remember that your system will be processing the traffic from the hosts you select. In other words, be sure to not to select too many hosts or everything will come to a standstill.

  Try 2 or 3 targets at the beginning and add additional from there if you wish.

  Supposing we want to intercept only the traffic of a specific host, we will add the target host and the router in the list.

  Therefore, if we want to run our attack on the host with IP address 172.16.5.15, we will select the targets as follow:
    ```
    Add to target 1: 172.16.5.15  | or | Add to target 1: 172.16.5.1
    Add to target 2: 172.16.5.1   |    | Add to target 2: 172.16.5.15
    ```

  Important:
    Please note that if you do not select a target, Ettercap will automatically set ANY (all the hosts) in the target list.

    As you can imagine, this will force your system to process a lot of traffic. Be sure your network and your machine can handle this amount of traffic, otherwise you may DoS your network.

Once we set the targets, we can select the type of attack to run. To do so let us click on the MitM in the top bar and choose among one of the following attacks:
  - ARP poisoning
  - ICMP redirect
  - Port stealing
  - DHCP spoofing

  For our first test we will select `ARP Poisoning`. Once we click on it, a pop-up window appears and we can select some options for the attack. For now let us enable the `Sniff remote connections` option and click OK.

  The ARP poisoning attack automatically starts and we should now be able to intercept the traffic of our target machine.

    To verify that the attack is working, let us first check our (the attacker) physical address.

    Then check the ARP table of the target machine (by running `arp -a`).
      It will show the MAC address(es) difference before and after the attack.

  Now that we know that the attack is working, let us click on `View->Connections` in order to inspect the traffic intercepted. As we can see, here is all the traffic generated from the target machine.

  In order to inspect the packets, we can double click on a connection listed in the previous view. A new tab appears, showing the details and the data transmitted.

  Ettercap will also automatically tries to intercept credentials sent via the network. Indeed we can see it was able to automatically gather the username and the password sent by the target host to the FTP server.

It is important to know that with the current configuration we can use other sniffing tools at the same time. For example, we can start Wireshark to sniff the `tap0` traffic.

You need to also know that some traffics are encrypted (i.e. SSL), but we can configure Ettercap later on in order to intercept and decrypt this traffic, but also what pitfalls and limits we may face.



#### 4.6.2. Cain & Abel: Sniffing and MitM Attacks
Another very powerful and infamous tool that we can use to mount MitM attacks is [Cain & Abel](http://www.oxid.it/cain.html).

To demonstrate how Cain works, we will use the same target used with Ettercap.

Steps (Image available):
  1. The first thing to do once Cain starts, is to `Configure` button in the top menu
    Ensure that you select the correct network adapter, and that you are sniffing in promiscuous mode.
    Also notice that some older wireless cards may not be able to sniff in promiscuous mode

  2. Once we are sure we have selected the correct interface to use, we have to select the `Sniffer` tab and start the sniffer by clicking on the `Start/Stop Sniffer` icon

  3. Now that we are in the correct window, let us right-click in the white space and select `Scan MAC address`. We need to  provide the address range to scan and Cain will automatically resolve IP to MAC based on ARP Request/Reply packets.

    As soon as we click `OK`, Cain starts scanning the network.
    After a few seconds we should see the hosts found listed in the main window. Similarly to Ettercap, we will run an ARP poisoning attack and use the host 172.16.5.15 and 172.16.5.1 (gateway) as targets.

  4. To intercept the data between these devices, we must now perform the ARP poisoning attack.


    ARP Poisoning steps:
    1. Let us click the ARP tab down at the bottom of the screen.
    2. Now that we are in the ARP tab, we have to click in the top white box and then click on the blue plus icon in the top menu.
      This will open a new window where we can select the targets of our test.
    3. In the new window we will see a list of host on the left. Once we select the router (172.16.5.1) on the left, the other hosts will show up on the right. With the router still selected on the left, let us then select our target (172.16.5.15) on the right.

      Notice that if you want to capture traffic from multiple hosts, you can hold down the CTRL key and click the other systems.

      In the next steps we will use only one victim (172.16.5.15).

    4. Now we are ready to activate the ARP poisoning by clicking on the ARP button in the main button (the Nuclear symbol).
      If everything is set correctly, we should now see the word `Poisoning` in the `Status` column.

      If the attack is working, we will start seeing packets in the bottom section of the windows, as follows:
      |   Status   |IP Address | MAC Address |Packets->|<-Packets| MAC Address | IP Address|
      |------------|-----------|-------------|---------|---------|-------------|------------------|
      |Full-routing|172.16.5.15|005056513404 |   40    |   40    |005056B139AF | 10.10.10.6 |
      |Full-routing|172.16.5.15|005056513404 |  17068  |  28096  |005056B139AF | 10.10.10.6 |

      We need to make a couple of notes here regarding the `ARP WAN Status` column in the bottom section of the window:
      - Broadcasting <br>
        The APR received a packet from a host on a different network directed to a host we are not poisoning. In order to ensure that the packet gets back to the host, ARP will broadcast the packet to all hosts on the LAN
      - Half-Routing <br>
        Means that APR is only routing traffic on one side of the connection (either client to server, or server to client), but not both sides

        There are couple of reasons this can happen:
        - One of the two hosts cannot be poisoned
        - Asymmetric routing is used on the LAN

        In this state, APR is limited in that it cannot grab any authentications that use challenge response mechanism for proper authentication. More than likely, the Poisoned system is still using the correct destination MAC address, so the traffic is bypassing the attacker system.

      - Full-Routing <br>
        This state means that APR is routing traffic successfully both ways, and all authentication will be captured accordingly.

    On the left panel we can see what Cain was able to intercept. If we inspect the entries by opening the `Password` tab, we will see the target machine (see image).

      If we inspect the entries by opening the `Password` tab, we will see the credentials sent by the target machine.

      You can continue to look at captured sessions by clicking on any of the items in the list on the left.

    Notice that Cain can be used to capture encrypted traffic too.

      In this case, it provides the target its own certificate, therefore it will be able to encrypt/decrypt the whole communication. (We will see this later on in this module)

One of the other powerful uses for Cain, is the interception of NTLM (NT LAN Manager) challenge spoofing.
  If a network utilizes Active Directory for authentication, Cain will be able to get the NTLM SHA1 hashed credentials from the network by spoofing the NTLM challenge response mechanism.

Moreover, any encrypted passwords can be sent to the Cain built-in **Cracker**, by right clicking on the line that contains the password that you need to decrypt and then clicking **send to cracker**

#### 4.6.3. Macof
As we already know, switches keep a translation table, known as the Content Addressable Memory (CAM) table. This table maps MAC addresses to the physical ports on the switch.

  In other words, the CAM table allows a switch to intelligently route packets from one host to another, but it has a limited memory for this function.

  This is how CAM table looks like:
    |PORT| MAC | TTL |
    |----|-----|-----|
    | 1  |MAC_A|1600 |
    | 1  |MAC_B| 90  |
    | 1  |MAC_C|1000 |
    | 2  |MAC_D| 36  |

MAC flooding makes use of this limitation of memory of the CAM table.
  It will flood the switch with fake MAC addresses, until the switch cannot keep up.
  This causes the switch to enter into what known as a **failopen mode**, wherein the switch begins acting as a network Hub by broadcasting packets to all the machines on the network.

  MAC flooding can be performed with both Ettercap and Cain, but we will see how to run the attack with **Macof**, a utility which comes with **dsniff suite**.

Macof can generate 155,000 MAC entries per minute, and generally takes less than 70 seconds to fill the CAM table on an average switch.

  Macof is a C version of the Perl module Net::RawIP macof program, originally written by Ian Vitek.

  Like many other tools, best results will come from running the tools as an administrator or root level user, or a user that has the same privileges on the system.

Basic Macof usage:
  ```
  macof [-s src] [-d dst] [-e tha] [-x sport] [-y dport] [-i interface ] [-n times]
  ```

  Description:
  - `-i` interface: Specify the interface to send on
  - `-s` src: Specify source IP address
  - `-d` dst: Specify destination IP address
  - `-e` tha: Specify target hardware address
  - `-x` sport: Specify TCP source port
  - `-y` dport: Specify TCP destination port
  - `-n` times: Specify the number of packets to send

Please note that using macof may cause degradation of network services, so be aware when running it in your network.

Also ensure that port forwarding is active on the attacking machine as describes earlier in the module. To do so, you can run the following command:
  ```
  echo 1 > /proc/sys/net/ipv4/ip_forward
  ```

For example:
  Let us run the command and set the interface `tap0` with the `-i` option:
    ```
    root@els: $ sudo macof -i tap0    
    ```

    At this point we can start a network sniffer, such as Wireshark or dnsiff, to start capturing data from the switch.

      If you are not seeing any data from other systems, then the router or switch you are trying to flood probably has protection against MAC flooding.

  Since the previous command will keep sending traffic, we can specify the amount of packets to send.
    For example, let us set them to 32 with the `-n` option, Once the 32 packets have been sent, Macof will automatically stop.

    This shortened command would only replace the first 32 listings in the table. Therefore would only get data from those ports until the switch times out the entry in the table and rediscovered the IP address of the device attached to the port.

#### 4.6.4. Arpspoof
Now we will take a look at ARPspoof, which executes the MitM attack that will allow us to sniff traffic.

This tool is part of dsniff package. It will constantly send ARP answers to our targets in order to poison its ARP table.

We will use the following test environment, same of the previous tests (see image):
  ```
  Target (Gateway)----------------Switch----------Victim    
    MAC : 00:50:56:B1:39:AF         |               MAC : 00:50:56:B1:34:04
    IP  : 172.16.5.1                |               IP  : 172.16.5.15
                                    |
                                    --------------Attacker
                                                    MAC : EA:75:03:7F:07:EB
                                                    IP  : 172.16.5.152

  ```

Steps:
1. Before running the tool, let us take a look at our victim machine and pull up the current ARP table on the system.
  To do this, we run the `arp -a` command from the prompt (see image).

  In the output we can see that the victim IP address is *172.16.5.15*, and that the router (*172.16.5.1*) MAC address is *00:50:56:B1:31:04*.

  Moreover the attacker (*172.16.5.152*) has the following MAC address: *EA:75:03:7F:07:EB*
2. Now that we know these information, we can go into our attacker machine and run the arpspoof that will start the attack by running `sudo arpspoof -i tap0 -t 172.16.5.15 172.16.5.1`:
    ```
    stduser@els:~$ sudo arpspoof -i tap0 -t 172.16.5.15 172.16.5.1
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ea:75:3:7f:7:eb 0:50:56:b1:31:4 0806 42: arp reply 172.16.5.1 is-at ea:75:3:7f:7:eb
    ```
    With this command we are sending ARP replies to the victim host (`-t 172.16.5.15`), telling that the MAC address of the host *172.16.5.1* (gateway) is our MAC address.

    Indeed, if we inspect the victim ARP table (using `arp -a`), we will see that the MAC address associated to the IP address *172.16.5.1* is changed and it is the same or our (attacker) machine (see image).

    **Notice that this is just half of the attack: the victim thinks we are the gateway, but the gateway still sends the packets to the correct victim MAC address.**

3. To complete the attack we have to run a new arpspoof command, similar to the previous one, but with the 2 IP addresses in the reverse order.
    This allows us to change the ARP table on the gateway too and be able to intercept the full communications between the victim and the gateway:
      ```
      sudo arpspoof -i tap0 -t 172.16.5.1 172.16.5.15
      ```

    Once we run the previous command, the MitM attack is complete and we will be able to intercept the victim traffic with external tool such as **Wireshark** or **tcpdump**

Important:
  Before running the arpspoof commands, be sure you have enabled IP forwarding on your attacker machine, so that the traffic goes through your host.

  You can do this with the following command:
    ```
    sudo echo 1 > /proc/sys/net/ipv4/ip_forward
    ```

#### 4.6.5. Bettercap
[Bettercap](http://www.bettercap.org/) is an open-source, modular, multi-platform, and offers a great amount of options and features that will allow us to highly configure our MitM attacks.

Once again we will use the same testing environment used so far and the same target machines. Like the tools we've seen so far, Bettercap implements an ARP spoofer feature that allows us to target both the whole network or a single known address.

[Basic commands](https://github.com/bettercap/bettercap/wiki):
  - `-h`
  - `-G` --gateway ADDRESS            Manually specify the gateway address
  - `-I` --interface IFACE            Network interface name
  - `-S` --spoofer NAME               Spoofer module to use
  - `-T` --target ADDRESS1.address2   Target IP address
         --ignore ADDRESS1.address2   Ignore addresses if found
  - `-O` --log LOG_FILE               Log all messages into a file
  - `-D` --debug                      Enable debug logging
  - `-L` --local                      Parse packets from/to the address of this PC
  - `-X` --sniffer                    Enable sniffer
  - `-P` --parser                     Enable parser
  - And others

Steps:
1. First, we need to find our targets in the network.
  To do so we can simply run Bettercap on a specific interface with the `--no-spoofing` option:
    ```
    bettercap -I tap0 --no-spoofing
    ```

  As we can see, only the discovery mode is enabled and the output shows that Bettercap is able to automatically identify the gateway (*172.16.5.1*), the other hosts in the network and their MAC addresses.

  Notice that by default it also attempts to perform a NBNS hostname resolution for each host, but we can disable this feature by adding the `--no-target-nbns` option to our command.

  Now that we know the alive hosts in our network, let us start configuring Bettercap.
    Notice that if we run it without any options, Bettercap by default will run a spoofing attack against all the host in the network.

2. Since we want to run the ARP spoofing attack on a specific target (172.16.5.15), we will use the `-T` option
  ```
  bettercap -I tap0 -T 172.16.5.15
  ```

  It is important to know that if Bettercap does not identify the correct gateway or not.
  If we want to manually specify a different gateway address, we can use the `-G` option followed by the IP address of the gateway.

  In our case, our command will look like the following:
    ```
    bettercap -I tap0 -G 172.16.5.1 -T 172.16.5.15
    ```

  Before running the previous command let us also enable the sniffer feature with the `-X` option. As stated in the [documentation](https://github.com/bettercap/bettercap/wiki), the credentials sniffer is able to dissect and print information such as: URLs visited, HTTP POST data, HTTP authentications, FTP credentials, and many more.

  We can decide what information to analyze but we can also use regex to capture the sniffed data.

  For now we will only enable the following: HTTPAUTH, FTP, URL, POST.

  Our final command will look like the following:
    ```
    bettercap -I tap0 -T 172.16.5.15 -X -P "HTTPAUTH,URL,FTP,POST"
    ```

  Once we run the command, Bettercap starts collecting URLs and data sent via POST/GET parameters.

__________________________
## 4.7. Intercepting SSL Traffic
Until now we focused on non-encrypted traffic. This section will go into what is necessary to perform MitM attacks on encrypted traffic.

The most important thing to remember here is how encrypted and SSL Certificates work. Because there is a handshake involved in the SSL protocol, it may be possible to intercept, decrypt, read, re-encrypt, and resend data.

The most common issue you will encounter here is that if you use a tool that generates self-signed certificates, it will more than likely cause a security exception on the victims machine.

Most often than not, we can rely on most users to just bypass that warning. However, recent browsers security features make it much more difficult for users to bypass those errors without further interrogation.

Before studying more advanced techniques, let us see how we can configure some of the previous tools in order to intercept and analyze SSL traffic.

  A few slides back, we saw that Ettercap was not able to analyze the clear text of a HTTPS connection.

  This happens because with the default Ettercap configuration we do not manipulate the traffic, instead we just intercept it and forward it to the target machine.

  What we need to do is to instruct Ettercap to create and use a fake SSL certificate that will be sent to the victim machine every time it tries to establish HTTPS connections.

  If the victim user accepts the certificate, Ettercap will be then able to decrypt the traffic.

  We can do this by editing a few options in the Ettercap configuration file.

    Let us open the file `/etc/ettercap/etter.conf` and edit it as follows. At the very beginning of the file, let us change the `uid` and the `gid` to `0`.

    Now, in the `redir_command_on/off` section, let us uncomment the following 2 lines. Notice that if you are using a different OS, you have to uncomment the correct lines in the files, according to the OS you are using.

  Once we edit the Ettercap configuration file, we can run our ARP poisoning attack and start sniffing our victim traffic.

  Now we should be able to intercept and read some of the HTTPS traffic too. Here Ettercap shows us that it was able to intercept some credentials:
    ```
    GROUP 2 : 172.16.1.10 00:0C:29:24:DD:54
    HTTP : 172.16.1.1:443 -> USER:Login PASS: INFO:https://172.16.1.1/
    CONTENT:__csrf_magic=sid%SD8FQ48GSDA8G8SD98ASD8F4SDFSA9FS9ADSDFS
    AS8DF78AS7F98ASF9AS89FSADF4ASFS98F7SD9F&usernamefld=admin&passwordfld=els&login=Login
    ```

It is important to know that whenever the victim tries to open a secure HTTP page, the browser will warn the user that the certificate in use is not correct.

#### 4.7.1. SSHStrip
Although most of the users will confirm the certificate exception, enhancements in SSL attack tools have found ways to exploit SSL without the need to inject a self-signed cert.

At [BlackHat 2009 Moxie Marlinspike](http://www.thoughtcrime.org/software/sslstrip/) introduced a new method for extracting information form a secure session by attacking HTTP. In order to demonstrate how this works, Marlinspike released a tool named [sslstrip](https://github.com/moxie0/sslstrip)

The way SSLStrip works:
1. Perform MitM attack on HTTPS connection between the victim and the server
2. Replaces the HTTPS links with HTTP clone links and remembers the links which were changed
3. Communicates with the victim client over HTTP connection for any secure link
4. Communicates with the legitimate server over HTTPS for the same secure link
5. The sslstrip attacker machine transparently proxies the communication between the victim and the server
6. Favicon images are replaced with the known *secure lock* icon to provide familiar visual confirmations
7. SSLStrip logs all traffic passing through. So, passwords, credentials, etc are stolen without the victim knowing.

By using these methods, the attacker is able to provide legitimate traffic to the client over an HTTP connection and provide visual feedback, such as the look icon, without getting the SSL Certificate errors normally associated with MitM attacks on SSL Traffic.

There are some issues that present themselves in this type of attack, for example:
- Some content encoding, such as gzip, is difficult to parse
- Cookies that are sent over HTTPS will not be sent over HTTP that has stripped the SSL
- Any cached pages which did not have the links swapped out

In order to counter these shortcomings, SSLStrip actually strips parts of the requests for this information:
- Stopping the secure bit on the `Set-Cookies` statements on the pages
- Strip the difficult encodings from the client requests
- Strip the `if-modified-since` headers to eliminate the cached pages being requested

By default SSLStrip uses port 10000 to listen for incoming connections, but we will instruct the tool to listen to a different port.

Moreover we also need an ARP spoofing tool in order to sniff the traffic from the victim. For the easiest and most reliable results, we will use Ettercap which already been discussed in the previous section.

The following are options that SSLStrip offers:
  Usage : `sslstrip <options>`
  Options:
  - `-w <filename>,--write=<filename>` Specify file to log to (optioanal)
  - `-p , --port`                      Log only SSL PORTs. (default)
  - `-s , --ssl`                       Log all SSL traffic to and from server
  - `-a , --all`                       Log all SSL and HTTP traffic to and from server
  - `-l <port>, --listen=<port>`       Port to listen on (default 10000).
  - `-f , --favicon`                   Substitute a lock favicon on secure requests
  - `-k , --killsessions`              Kill sessions in progress
  - `-h`                               Print this help message

In the next part we will use Ettercap to mount an ARP poisoning MitM attack and SSLStrip to capture the encrypted traffic.
  Before starting be sure to:
  1. Enable the IP forwarding:
      ```
      echo 1 > /proc/sys/net/ipv4/ip_forward
      ```

  2. Set up port redirection using iptables
      ```
      iptables -t net -A PREROUTING -p top --destination-port 80 -j REDIRECT --to-port 8080
    ```

Step on SSLStrip:
1. Now we can start SSLStrip and instruct it to listen on port 8080
  Moreover, we use the `-w` option to save the logs into a specific file, but we also use the `-f` option to instruct SSLStrip to substitute the favicon on secure requests.

  Our command will look like the following:
    ```
    sslstrip -a -f -l 8080 -w els_sslt
    ```

2. The last step is to configure Ettercap in order to mount an ARP MitM attack between victim and gateway.

  Once everything is up and running, we can move into the victim machine and execute a secure web session.
  In this case we will use a Windows Live login. As we can see, the URL contain HTTP and the favicon has been substituted with a lock icon.

  Now, as soon as we try to log into the portal, Ettercap will display the request and credentials sent by the victim.

Similarly to Ettercap, other tools can also be used in conjunction with SSLStrip. Bettercap already implements SSLStrip, thus we can run the whole attack in just one command by using the `--proxy-https` option.

  Let us suppose the target gateway is 192.168.102.2, while the victim is 192.168.102.135. Our command will be:
    ```
    bettercap -G 192.168.102.2 -T 192.168.102.135 --proxy-https
    ```
    As we can see in the tool output (see image), the `https-proxy` feature and `sslstrip` are now enabled. From this moment on, if the victim tries to open an HTTPS link, it will be automatically stripped down to HTTP.

  Let us try to navigate some pages from the victim machine and see what we get in out terminal.

    As we can see (see image), when the victim tries to load HTTPS page, such as `https://live.com`, ssltrip intercepts the request and strips down the request to HTTP. Notice that it does this for each link or request it finds.

Something that you will notice during your test is that this technique does not work anymore with some websites and with newer web browser.
  In the following screenshot we can see that opening the Facebook login page from Internet Explorer and Google Chrome gives our different results.

  This happens because the HTTP Strict Transport Security ([HSTS](https://tools.ietf.org/html/rfc6797)) policy mechanism in place. HSTS is a security enhancement specifies by the web application and that prevents the protocol downgrade from HTTPS to HTTP.

  If the browser supports this features, it forces the communications t o HTTPS, by redirecting HTTP requests to HTTPS. [Here](http://caniuse.com/#feat=stricttransportsecurity) you can see the list of browsers that support this feature.

It is important to know that this attack works fine if the victim tries the connection to the web site for the first time. This happens because the web browser does not know whether or not to use a secure connection, since it never received the HSTS header.

In order to defeat this issue, web browser implemented the so called (preload list)[https://code.google.com/p/chromium/codesearch#chromium/src/net/http/transport_security_state_static.json], which contain sites that have to be accessed with a secure connection, even if it is the first time.

Here you can find more references about HSTS and loaded lists:
- (Chromium Preloaded List)[https://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json]
- (Mozilla: Preloading HSTS)[https://blog.mozilla.org/security/2012/11/01/preloading-hsts/]
- (Chrome HSTS)[https://src.chromium.org/viewvc/chrome/trunk/src/net/http/transport_security_state_static.json]
- (Internet Explorer HSTS)[https://support.microsoft.com/en-us/kb/3071338]

#### 4.7.2. HSTS Bypass (MITMf)
In order to (partially bypass this security feature, Leonardo Nve Egea) presented at (Black Hat 2014)[http://www.slideshare.net/Fatuo__/offensive-exploiting-dns-servers-changes-blackhat-asia-2014] a new version of sslstrip named (sslstrip+)[https://github.com/singe/sslstrip2]

Many MitM tools started implementing *sslstip+* in order to bypass HSTS. The one we are going to see in this section is called [MITMf](https://github.com/byt3bl33d3r/MITMf)


Before seeing the tool in action, let us get a better idea of how the attack works:
  In addition to the modified version of *sslstip*, we now need to run a DNS server too. In this way, we will be able to intercept and edit the victim's DNS requests, and bypass HSTS.




__________________________
