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



__________________________
## 4.5. Man in the Middle Attacks


__________________________
## 4.6. Attacking Tools


__________________________
## 4.7. Intercepting SSL Traffic


__________________________
