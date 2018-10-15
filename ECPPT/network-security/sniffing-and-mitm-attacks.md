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
  It does not need to bring down switch functionalities, instead it expoloitsthe concept of traffic redirection.
  This is one of the most used attacks to perform Man in the Middle Attacks.

__________________________
## 4.3. Basic of ARP


__________________________
## 4.4. Sniffing Tools


__________________________
## 4.5. Man in the Middle Attacks


__________________________
## 4.6. Attacking Tools


__________________________
## 4.7. Intercepting SSL Traffic


__________________________
