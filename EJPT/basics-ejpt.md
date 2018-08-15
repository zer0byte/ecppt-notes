## Preliminary Skills
---------------------------------
# A. Networking
## 1. Protocols
### a. ISO/OSI Layers
In networking there are things that are called 'layers' and each of them sends out 'packets' or protocol data unit (PDU).
Packet on the lower layer wraps the packet above them upon sending and unwraps them upon receiving.

Below are the OSI layers structure:
- Layer 7 : Application Layer
- Layer 6 : Presentation Layer
- Layer 5 : Session Layer
- Layer 4 : Transport Layer
- Layer 3 : Network Layer
- Layer 2 : Data Link Layer
- Layer 1 : Physical Layer


Descriptions:
##### 1. Physical Layer (Rarely talked about)
Physical layer governs the transmission of raw bit streams over physical medium such as cables or electromagnetic signals.

PDU : Symbol, simplex, half duplex, full duplex<br>
Devices : Hubs, Repeaters, Cables, Wireless

##### 2. Data Link Layer
Data link layer governs reliable transmission of data frames between two nodes connected by a physical layer.

According to IEEE 802, this layer is seperated into 2 layers:
- MAC (Medium Access Control) layer
responsible for controlling how devices in a network gain access to a medium and permission to transmit data. MAC Address : an address unique to each machine
- LLC (Logical Link Control) layer
responsible for identifying and encapsulating network layer protocols and controls error checking and frame synchronization

PDU : Frame<br>
Protocols : MAC, PPP (Point-to-Point Protocol), 802.11 Wi-Fi, 802.3 Ethernet, sliding-window protocol<br>
Devices : Bridges, Modems, Network Cards, 2-Layer Switches

##### 3. Network Layer
Network layer governs structuring and managing a multi-node network, including addressing, routing and traffic control

PDU : Packet<br>
Protocols : IP<br>
Devices : Routers, Brouters, 3-layer switches

##### 4. Transport Layer
Transport layer governs reliable transmission of data segments between points on a network, including segmentation, acknowledgement and multiplexing

PDU : Segment, Datagram<br>
Protocols : TCP, UDP, tunneling protocols<br>
Devices : Gateways, Firewalls

##### 5. Session Layer
Session layer governs managing communication sessions, i.e. continuous exchange of information in the form of multiple back-and-forth transmissions between two nodes

PDU : Data<br>
Devices : Gateways, Firewalls

##### 6. Presentation Layer
Presentation layer governs translation of data between a networking service and an application; including character encoding, data compression and encryption/decryption

PDU : Data<br>
Devices : Gateways, Firewalls

##### 7. Application Layer
Application layer governs high-level APIs, including resource sharing, remote file access

PDU : Data<br>
Protocols : HTTP, FTP<br>
Devices : Gateways, Firewalls

## 2. IP
##### 1. IPv4 Addresses
IPv4 uses 32-bit addresses.

|  172  |   16   |  254   |   1  |
|-------|--------|--------|-------|
|1010110|00010000|11111110|00000001|

There are 5 classes of IP:

|Class   | Address Range|
|--------|--------------|
|Class A | 1.0.0.1 to 126.255.255.254|
|Class B | 128.1.0.1 to 191.255.255.254|
|Class C | 192.0.1.1 to 223.255.254.254|
|Class D | 224.0.0.0 to 239.255.255.255|
|Class E | 240.0.0.0 to 254.255.255.254|

##### 2. Reserved IP addresses
There are several IP addresses that cannot be used: <br>
**Bolded** addresses are common

|Address block|Address range|Number of addresses | Scope | Description |
|------|-------|-------|-------|-------|
| **0.0.0.0/8** | 0.0.0.0-0.255.255.255.255 | 2^(32-8) = 2^24 = 16 777 216 | Software | Current network (only valid as source addresses) |
| **10.0.0.0/8** | 10.0.0.0-10.255.255.255 | 16 777 216 | Private Network | Used for local communications within a private network |
| 100.64.0.0/10      | 	100.64.0.0–100.127.255.255 | 4 194 304 | Private Network | Shared address space for communications between a service provider and its subscribers when using a carrier-grade NAT. |
| **127.0.0.0/8**       | 	127.0.0.0–127.255.255.255 | 16 777 216 | Host | Used for loopback addresses to the local host |
| 169.254.0.0/16     | 	169.254.0.0–169.254.255.255 | 65536 | Subnet | Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified, such as would have normally been retrieved from a DHCP server. |
| 172.16.0.0/12      | 172.16.0.0–172.31.255.255 | 1 048 576 | Private Network | Used for local communications within a private network. |
| 192.0.0.0/24       | 192.0.0.0–192.0.0.255 | 256 | Private Network | IETF Protocol Assignments |
| 192.0.2.0/24       | 	192.0.2.0–192.0.2.255 | 256 | Documentation | Assigned as TEST-NET-1, documentation and examples |
| 192.88.99.0/24     | 192.88.99.0–192.88.99.255 | 256 | Internet | Reserved. Formerly used for IPv6 to IPv4 relay (included IPv6 address block 2002::/16). |
| **192.168.0.0/16**     | 	192.168.0.0–192.168.255.255 | 65536 | Private Network | Used for local communications within a private network |
| 198.18.0.0/15      | 	198.18.0.0–198.19.255.255 | 131 072 | Private Network | Used for benchmark testing of inter-network communications between two separate subnets. |
| 198.51.100.0/24    | 	203.0.113.0–203.0.113.255 | 256 | Documentation | Assigned as TEST-NET-2, documentation and examples |
| 203.0.113.0/24     | 224.0.0.0–239.255.255.255 | 256 | Documentation | Assigned as TEST-NET-3, documentation and examples |
| **224.0.0.0/4**        | 224.0.0.0–239.255.255.255	 | 268435456 | Internet | In use for IP multicast (Former Class D network) |
| 240.0.0.0          | 240.0.0.0–255.255.255.254 | 268435456 | Internet | Reserved for future use (Former Class E network) |
| **255.255.255.255/32** | 255.255.255.255 | 268435456 | Subnet | Reserved for the "limited broadcast" destination address |

##### 3. IP/Mask and CIDR
- Subnet mask<br>
Subnet mask is a number that governs which part of IP should be read. Subnet mask can be represented by numbers between 1-32, ordered bitmap with the length of 32 (4 byte), or the number representation of the bitmap (ie: 255.255.255.0).<br>
Why use subnet mask?<br>
For example you have a class C IP from 192.168.1.0-192.168.255/24 and you want to split it into 2 seperate networks. You can make the subnet mask to 25 to 2 networks as in table below.

|Network address (24 bits) | Subnet number (1 bit) | Extended network | Host address range|
|--------|--------|--------|--------|
| 11000000 10101000 00000001 | 0 | 192.168.1.0     | 192.168.1.1-192.168.1.127 |
| 11000000 10101000 00000001 | 1 | 192.168.1.128 | 192.168.1.129-192.168.1.255 |

[Subnet Calculator](http://www.subnet-calculator.com/)

- CIDR Notation <br>
The method of writing subnet mask with IP (i.e : 192.168.102.0/24)

##### 4. Network and Broadcast Addresses
Network address usually located in the first address of a network (ie: 192.168.1.0).<br>
Broadcast address usually located in the last address of a network (ie: 192.168.1.255)

## 3. Routing
a. Routing table<br>
Each router keep one of these:

| Network Destination | Netmask | Gateway | Interface | Metric|
|-----|-----|------|------|-----|
| 127.0.0.0 | 255.0.0.0 | 127.0.0.1 | 127.0.0.1 | 1 |
|...|...|...|...|...|...|

Description :
  + Network destination and netmask : shows range of ip covered by a particular gateway
  + Gateway : holds the address on where to go to get to the address on the left
  + Interface : indicates what is locally available to connect to the gateway
  + Metric : Cost of using the indicated route. Lower cost is preferred

b. NAT<br>
Is a method of remapping one IP address space into another by modifying network address information in the IP header of packets while they are in transit across a traffic routing device.

c. Steps
1. Is the destination directly connected?<br>
Is this true, for one of my network interfaces?<br>
( my_ip AND netmask ) = ( destination_IP AND netmask )<br>
If so, use ARP to find the MAC address and deliver the frame directly across the attached network.
Send an ARP request, a broadcast frame on the local network that will not be forwarded by routers. It takes the form, "I am looking for the device using IP address such-and-such. Who has it?"<br>
Expect to receive an ARP reply, a response from the requested host, of the form "I have that IP address, and here is my MAC address". Then send the packet, encapsulated as:<br>
MAC: destination MAC address<br>
IP: destination IP address<br>
If not, continue...
2. Do I have a host-specific route?<br>
Is there a route to exactly that one IP address? This will be a route with a netmask of /32, or 255.255.255.255, meaning "All of the address bits must be as specified."<br>
If so, do what that route says.<br>
That route will specify forwarding the packet through some directly-connected router. So, first you have to find that router's MAC address so you can send the frame across the LAN.<br>
If not, continue...<br>
3. Do I have a network-specific route?<br>
Do I have a routing table entry where the following is true, where both route and netmask are the values from that entry?<br>
( route AND netmask ) = ( destination_IP AND netmask )<br>
If so, do what that route says.<br>
That route will specify forwarding the packet through some directly-connected router. So, first you have to find that router's MAC address so you can send the frame across the LAN.<br>
If not, continue...<br>
4. Do I have a default route?<br>
If so, do what that route says.<br>
That route will specify forwarding the packet through some directly-connected router. So, first you have to find that router's MAC address so you can send the frame across the LAN.<br>
If not, continue...<br>
5. The packet is unrouteable! Report an error! <br>
Send an ICMP message to the originating host, type "Destination Unreachable" and specifically "Network Unreachable".<br>
The formal definition says that this should not be done if the unroutable packet is itself ICMP, because that would be using ICMP to report errors about ICMP and that process that might spiral out of control. However, Microsoft's tracert does not correctly implement traceroute, it uses ICMP packets with artificially small TTL values rather than the specified UDP. So, many implementations will report errors for unroutable ICMP to support Microsoft's non-compliant implementation.

## 4. Link Layer Devices and Protocols
###### [MAC Addresses](https://en.wikipedia.org/wiki/MAC_address)
MAC Address is an unique identifier of each device in the world. It consists of 48-bit address.
##### IP and MAC Addresses
Both IP address and MAC Address are needed to fill an IP frame. To find out a MAC Address from IP address you can use [ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol). For the reverse, you can check the DHCP server, check on routing table what MAC address each entry is, or 'ask' all of them manually using ping sweep.

##### Broadcast MAC Addresses
In the cast of a broadcast message, use broadcast IP (last address of a subnet) and broadcast MAC, which is FF:FF:FF:FF:FF:FF.

## 5. TCP and UDP
##### [TCP](https://en.wikipedia.org/wiki/Transmission_Control_Protocol)<br>
Motto : Reliability over Speed
A TCP packet consists of flags, most notable ones are SYN, ACK, and SEQ. It indicates the state of the connection.
a. Connection Establishment<br>
TCP uses three way handshake in its connection:<br>
  1. Client send a SYN to server
  2. Server send a SYN-ACK response. <br>
  ACK (sent) = SEQ + 1. <br>
  Sequence number is random
  3. Client sends an ACK back to server <br>
  SEQ = ACK (received) <br>
  ACK (sent) = SEQ (received) + 1

b. Connection Termination <br>
Connection termination phase uses a four-way handshake, with each side of the connection terminating independently. <br>
  1. FIN is sent from one endpoint to another (ie: A)
  2. ACK is sent from the receiving endpoint (ie: B)
  3. FIN is sent from the B to A (steps 3 and 4 is usually done together)
  4. ACK is sent from A to B

c. Sending Data<br>
Each time data is sent, whether from client to server ot from server to client, the ACK and SEQ flags are set, following this rules for each consecutive package:<br>
SEQ = ACK (received) <br>
ACK (sent) = SEQ (received) + 1 <br>

d. Other important terms
- Sliding window<br>
Usually, packets in TCP are sent in groups. This group members are set with a 'window', which is  number of consecutive packets currently sent, and is waiting for ACKs. Data on the next group will be proceed to be sent if the data on the previous group has received its ACKs. If not, resent will be done. If one or more early-numbered-window packet are done, the window will 'slide' to include different packet on the group.

- Slow Start
This scheme increased the size of window over successful connections done and decreases the size of window over unsuccessful ones. The increase is first on the power of 2, then it went linear as time goes

- Additive Increase / Multiplicative Decrease
The same as slow start, but the increase is linear.

##### [UDP](https://en.wikipedia.org/wiki/User_Datagram_Protocol)
Motto : Speed over Reliability
With UDP, data is sent as streams, without taking consideratoin whether it reaches its target or not.

Dynamic Host Configuration Protocol (DHCP) is a network management protocol used on UDP/IP networks whereby a DHCP server dynamically assigns an IP address and other network configuration parameters to each device on a network so they can communicate with other IP networks.

##### Ports
Here are some important port numbers:

| Port | Usage |
|------|-------|
|1|TCP Port Service Multiplexer|
|5|Remote Job Entry|
|7|ECHO|
|18|Message Send Protocol (MSP)|
|20|FTP -- Data|
|21|FTP -- Control|
|22|SSH Remote Login Protocol|
|23|Telnet|
|25|SMTP|
|29|MSG ICP|
|37|Time|
|42|Host Name Server (Nameserv)|
|43|WhoIs|
|49|Login Host Protocol (Login)|
|53|DNS|
|69|Trivial File Transfer Protocol (TFTP)|
|70|Gopher Services|
|79|Finger|
|80|HTTP|
|103|X.400 Standard|
|108|SNA Gateway Access Server|
|109|POP2|
|110|POP3|
|115|Simple File Transfer Protocol (SFTP)|
|118|SQL Services|
|119|Newsgroup (NNTP)|
|137|	NetBIOS Name Service|
|139|NetBIOS Datagram Service|
|143|	Interim Mail Access Protocol (IMAP)|
|150|NetBIOS Session Service|
|156|SQL Server|
|161|SNMP|
|179|Border Gateway Protocol (BGP)|
|190|	Gateway Access Control Protocol (GACP)|
|194|	Internet Relay Chat (IRC)|
|197|	Directory Location Service (DLS)|
|389|Lightweight Directory Access Protocol (LDAP)|
|396|	Novell Netware over IP|
|443|HTTPS|
|444|Simple Network Paging Protocol (SNPP)|
|445|Microsoft-DS|
|458|Apple QuickTime|
|546|DHCP Client|
|547|DHCP Server|
|563|SNEWS|
|569|MSN|
|1080|Socks|

## 6. [Firewalls](https://en.wikipedia.org/wiki/Firewall_(computing) and Defense Systems
Firewall is software or firmware that enforces a set of rules about what data packets will be allowed to enter or leave a network<br>

##### Packet-Filtering Firewalls

Compares each packet received to a set of established criteria -- such as the allowed IP addresses, packet type, port number, etc. Packets that are flagged as troublesome are, generally speaking, unceremoniously dropped -- that is, they are not forwarded and, thus, cease to exist.

##### Application Layer Firewalls
(Technically a proxy) It filters packets not only according to the service for which they are intended -- as specified by the destination port -- but also by certain other characteristics, such as the HTTP request string.

##### [Intrusion Detection System] (https://en.wikipedia.org/wiki/Intrusion_detection_system)
Intrusion detection system (IDS) is a device or software application that monitors a network or systems for malicious activity or policy violations

##### Intrusion Prevention System
Intrusion prevention systems are basically extensions of intrusion detection systems. The major difference lies in the fact that, unlike intrusion detection systems, intrusion prevention systems are installed are able to actively block or prevent intrusions that are detected

##### NAT and Masquerading
NAT describes the process of modifying the network addresses contained with datagram headers while they are in transit. This might sound odd at first, but we'll show that it is ideal for solving the problem we've just described and many have encountered. IP masquerade is the name given to one type of network address translation that allows all of the hosts on a private network to use the Internet at the price of a single IP address.

Source NAT changes the source address in IP header of a packet. It may also change the source port in the TCP/UDP headers. The typical usage is to change the a private (rfc1918) address/port into a public address/port for packets leaving your network.

Destination NAT changes the destination address in IP header of a packet. It may also change the destination port in the TCP/UDP headers.The typical usage of this is to redirect incoming packets with a destination of a public address/port to a private IP address/port inside your network.

Masquerading is a special form of Source NAT where the source address is unknown at the time the rule is added to the tables in the kernel. If you want to allow hosts with private address behind your firewall to access the Internet and the external address is variable (DHCP) this is what you need to use. Masquerading will modify the source IP address and port of the packet to be the primary IP address assigned to the outgoing interface. If your outgoing interface has a address that is static, then you don't need to use MASQ and can use SNAT which will be a little faster since it doesn't need to figure out what the external IP is every time.


## 7. [DNS](https://en.wikipedia.org/wiki/Domain_Name_System)
DNS (Domain Name System) is a group a server that translates domain name into IPs. DNS have several hierarchies, with the root hierarchy named '.'. When a computer looks for a domain name, it started looking on the local DNS Server. We can lookup a DNS using nslookup command
##### Types of DNS Record
- State of Authority (SOA)
- IP Addresses (A and AAAA)
- SMTP mail exchangers (MX)
- Name Servers (NS)
- Pointers for reverse DNS lookups (PTR)
- Domain name aliases (CNAME)

## 8. Wireshark
----------------------------------
# B. Web Applications
## 1. [HTTP](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)
Like any other protocols, HTTP has its own 'frame' and header with several fields. HTTP works with a request-response model. A client HTTP Requests a web page, then the server replies with a HTTP Response

###### HTTP Request
A HTTP request message consists of the following:
- A request line : METHOD /path HTTP/version (e.g., GET /index.html HTTP/1.1)
- Request header fields (e.g., Accept-Language: en), must end with <CR><LF>
- An empty line (must consists only <CR><LF>)
- An optinal message body


HTTP defines [methods](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods) to indicate the desired action to be performed on the identified resource:
| HTTP Method | Usage (Normally)|
|-------------|-------|
| **GET**     | to fetch a data |
| HEAD    | identical to GET, but without response body |
| **POST**    | to create new entry of data |
| **PUT**     | to update a data record |
| **DELETE**  | to delete a data record |
| CONNECT | establishes a tunnel to the server identified by a target|
| OPTIONS  | to describe the communication options for the target resource. |
| TRACE   | performs a message loop-back test along the path to the target resource |
| PATCH   | to apply partial modifications to a resource |

###### HTTP Response
HTTP response message consists of the following:
- A status line which includes the status code and reason message (e.g., HTTP/1.1 200 OK)
- Response header fields (e.g., Content-Type: text/html), must end with <CR><LF>
- An empty line (must consists only <CR><LF>)
- An optional message body

Below are several official response status that may be returned in HTTP response:
|Status Code|Description|
|-----------|-----------|
|**1xx**|**Informational Responses**|
|100|Continue|
|101|Switching Protocols|
|**2xx**|**Success**|
|200|OK|
|201|Created|
|202|Accepted|
|203|Non-Authoritative Information|
|**3xx**|**Redirection**|
|300|Multiple Choices|
|301|Moved Permanently|
|302|Found|
|308|Permanent Redirect|
|**4xx**|**Client Errors**|
|400|Bad Request|
|401|Unauthorized|
|403|Forbidden|
|404|Not Found|
|405|Method not Allowed|
|407|Proxy Authentication Required|
|408|Request Timeout|
|**5xx**|**Server Errors**|
|500|Internal Server Error|
|501|Not Implemented|
|502|Bad Gateway|
|503|Service Unavailable|
|505|HTTP Version not supported|

Below are several unofficial response status that may be returned in HTTP response:
|Status Code|Description|
|-----------|-----------|
|440|Login Time-Out (IIS)|
|444|No Response (nginx)|
|495|SSL Certificate Error (nginx)|
|496|SSL Certificate Requried (nginx)|

###### HTTPS
Basically layers a SSL on top of HTTP protocol.

##### [SSL](https://robertheaton.com/2014/03/27/how-does-https-actually-work/)
An SSL connection between a client and server is set up by a handshake. The handshake consists of 3 main phases:
1. Hello
The handshake begins with the client sending a ClientHello message. This contains all the information the server needs in order to connect to the client via SSL, including the various cipher suites and maximum SSL version that it supports. The server responds with a ServerHello, which contains similar information required by the client, including a decision based on the client’s preferences about which cipher suite and version of SSL will be used.
2. Certificate Exchange
Server proves to the client (or to another server) about their identitiy using a SSL certificate. SSL certificate are signed by one of several agreed Certificate Authorities (CAs) to ensure its validity.

3. Key Exchange
Client and server exchanges the agreed key for symmetric encryption using asymmetric encryption. The symmetric encryption then used for encrypting and decrypting messages sent.

## 2. HTTP Cookies
HTTP cookie is an entry of data that informs the server about a client.
##### Structure
The structure of HTTP cookies are:
1. Name
2. Value
3. Zero or more attributes

##### Types of Cookies
- Session cookie
 Also known as non-persistent cookie, exists only in temporary memory while the user navigates the website. Web browsers normally delete session cookies when the user closes the browser. Unlike other cookies, session cookies do not have an expiration date assigned to them, which is how the browser knows to treat them as session cookies.

- Persistent cookie
A persistent cookie expires at a specific date or after a specific length of time

- Secure cookie
A secure cookie can only be transmitted over an encrypted connection

- HTTP-only cookie
An http-only cookie cannot be accessed by client-side APIs, such as JavaScript. A cookie is given this characteristic by adding the `HttpOnly` flag to the cookie.

- Same-site cookie
In 2016 Google Chrome version 51 introduced a new kind of cookie, the same-site cookie, which can only be sent in requests originating from the same origin as the target domain. This restriction mitigates attacks such as cross-site request forgery (XSRF). A cookie is given this characteristic by setting the `SameSite` flag to `Strict` or `Lax`.

- Third party cookie
Normally, a cookie's domain attribute will match the domain that is shown in the web browser's address bar. This is called a first-party cookie. A third-party cookie, however, belongs to a domain different from the one shown in the address bar. This sort of cookie typically appears when web pages feature content from external websites, such as banner advertisements. This opens up the potential for tracking the user's browsing history and is often used by advertisers in an effort to serve relevant advertisements to each user.

- Super cookie
A supercookie is a cookie with an origin of a top-level domain (such as .com) or a public suffix (such as .co.uk). Ordinary cookies, by contrast, have an origin of a specific domain name, such as example.com.

- Zombie cookie
A zombie cookie is a cookie that is automatically recreated after being deleted

## 3. Sessions
User sessions (whether a user is considered logged in or logged out) is managed with session cookies (or in several cases same-site cookies)

## 4. Same Origin Policy
In computing, the same-origin policy is an important concept in the web application security model. Under the policy, a web browser permits scripts contained in a first web page to access data in a second web page, but only if both web pages have the same origin. An origin is defined as a combination of URI scheme, host name, and port number. This policy prevents a malicious script on one page from obtaining access to sensitive data on another web page through that page's Document Object Model.

This mechanism bears a particular significance for modern web applications that extensively depend on HTTP cookies[1] to maintain authenticated user sessions, as servers act based on the HTTP cookie information to reveal sensitive information or take state-changing actions. A strict separation between content provided by unrelated sites must be maintained on the client-side to prevent the loss of data confidentiality or integrity.

## 5. [Burp Suite](https://portswigger.net/burp/help/suite_gettingstarted)
