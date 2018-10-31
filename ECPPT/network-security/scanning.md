# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# Network Security
# Module 2 - Scanning

https://cdn.members.elearnsecurity.com/ptp_v5/section_2/module_2/html/index.html

__________________________
## 2.1. Introduction
#### 2.1.1. Ports, Protocols, and Services
Ports, Protocols, and Services (PPS) help us in identifying the types of  application running on a system and subsequently any potential weaknesses.
This is due to the fact that, in the past, security researchers not only discovered vulnerabilities for specific applications, but also, created exploits that would allow adversaries to take advantage of these weaknesses.

In order to effectively utilize PPS information, one must know where to uncover information about services and applications running on a specific port. This is also valid for potential malware that may already exist on the target systems.

While there are many references available on the internet, having a locally stored copy ready for easy reference is always beneficial.

Good reference for PPS: [Service Name and Transport Protocol Port Number Registry](http://www.iana.org/assignments/port-numbers)

Of course, you can always use search engines to find this information, but be sure to search for recent posting dates, as many of the available resources are dead.

The best option in identifying PPS would be to scan all ports of the remote system. Despite the fact that this is true, you should be aware that scanning all 65535 ports takes a very long time. Moreover, this type of scan will surely expose you presence on the network. Therefore, it is best to create jobs for specific smaller port ranges.

By default, most of the tools that we are going to use scan only a small set of ports. This means that they will scan only the most common applications and services such as telnet, FTP, SSH, HTTP, etc.

Note:
A skilled network administrator may deploy anti-enumeration techniques. In addition, network administrator may deploy a service to a port that commonly identifies as hosting malware.

#### 2.1.2. TCP - Three Way Handshake
All TCP based connection begin with a simple exchange of messages called three way handshake.

Header fields involved in the handshake:
- Sequence number
- Acknowledgement number
- SYN and ACK flags
```
0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Source Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Acknowledgement Number    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data  |           |U|A|P|R|S|F|
|Offset | Reserved  |R|C|S|S|Y|I|
|       |           |G|K|H|T|N|N|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Steps:
1. First, the client sends a TCP packet to the server<br>
  This packet has the SYN flag enabled and a random sequence number set (i.e.: Client **-SYN--[Seq:329 Ack:0]->** Server)
2. Then, the server replies by sending a packet with both SYN and ACK flag set and contains another random sequence number<br>
  The ACK number is always a simple increment of the SYN number sent by the client (i.e.: Client **<-SYN/ACK--[Seq:498 Ack:330]-** Server)
3. Finally, the client completes the synchronization by sending an ACK packet<br>
  Note that the client behaves just like the server when sending ACK packets (i.e.: Client **-SYN--[Seq:330 Ack:449]->** Server)

More resources:
- [IP Layer Network Administration with Linux](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_2_attachment_IP_Layer_Network_Administration_with_Linux)
- [TCP/IP Tutorial and Technical Overview](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_2_attachment_TCPIPTutorialAndTechincalOverview)
- [Packet Analysis Reference Guide v3.0.](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_2_attachment_Packet_Analysis_Reference_Guide_v30)
- RFC for communication protocols

__________________________
## 2.2. Detect Live Hosts and Ports
We will see how to detect open ports, identify services, operating systems, and much more.

It is important to know that with the advent of protocol security in both firewalls and routers, this process has become quite a bit more difficult than it used to be.
We must also keep in mind that, based upon the type of discovery launched against the target, the level of noise produced varies therefore, making it essential that we are aware of the various scanning and enumeration techniques we decide to use.
For example, running a straight ping sweep of a network is surely going to announce that we are there and we have started identifying their systems. On the other hand, a very random RCP connect scan may appear to administrators as normal connect requests to hosts, but this takes longer time.

There are several tools that are essential to network enumeration:
- Nmap
  Nmap is network enumeration and auditing tool. This tool is used to identify alive hosts, open ports, and so on. Nmap need to be run in root or administrator privilleges in order to operate.

  Basic command line format of nmap:
  ```
  nmap <scan_type> <options> <target>
  ```

  **Host discovery techniques:**
  - `-sL` : List Scan - Simply list targets to scan
  - `-sn` : Ping Scan - disable port scan
  - `-Pn` : Treat all hosts as online -- skip host discovery
  - `-PS/PA/PU/PY[portlist]` : TCP SYN/ACK, UDP or SCTP discovery
  - `-PE/PP/PM` : ICMP echo, timestamp, netmask request discovery
  - `-PO[protocol list]` : IP Protocol Ping
  - `-n/-R` : Never do DNS resolution/Always resolve
  - `--dns-servers <serv1[,serv2],...>` : Specify custom DNS servers
  - `--system-dns` : Use OS's DNS resolver
  - `--traceroute` : Trace hop path to each host

  [Scanning techniques](https://nmap.org/book/man-port-scanning-techniques.html) (Get information about open/closed/filtered ports):
  - `-sS/sT/sA/sW/sM`: TCP SYN/Connect()/ACK/Window/Maimon scans
  - `-sU`: UDP Scan
  - `-sN/sF/sX`: CP Null, FIN, and Xmas scans
  - `--scanflags <flags>`: Customize TCP scan flags
  - `-sI <zombie host[:probeport]>`: Idle scan
  - `-sY/sZ`: SCTP INIT/COOKIE-ECHO scans
  - `-sO`: IP protocol scan
  - `-b <FTP relay host>`: FTP bounce scan

  **Scanning Techniques**
  - TCP SYN Scan `-sS` <br>
    SYN scans are the most popular type of scans as they can both be performed quickly and, are not as obtrusive as other types of scan.
    A SYN scan is also one of the more accurate scans for determining if a discovered port is in an open, closed, or in a filtered state.

    Since the SYN scan does not open a full TCP connection, it is often referred to as half-opening scanning.
    This is how it works:
    - Nmap sends the SYN packet to open the communications and then awaits the response to determine the port states
    - If a SYN/ACK message is received, nmap knows the port is open.
      If a RST (reset) flag is received, nmap will report the port as closed or not after actively listening
    - After receiving the response, our machine closes the connection sending a RST packet

    In the event that no response is received after several attempts, nmap will report the port as filtered. A port will also marked as filtered in the event that an ICMP unreachable error is returned as a response

  - TCP Connect Scan `-sT`
    TCP connect scan is the default type of TCP scan when SYN scan is not an option.
    This type of scan is also used in the case of a network utilizing the IPv6 protocol.

    With TCP connect scan, nmap relies on the underlying operating system to establish a TCP connection to the target host, and therefore it does not utilize raw packets as with most other scans.

    Since nmap is relying on the OS to perform the connection, it naturally has less reliable results compared to raw packets, therefore, is less efficient.

    This is how it works:
    - Nmap sends the SYN packet to open the communications
    - Once the target machine responds with the SYN-ACK, out host completes the communication by sending an RST-ACK. Establishing a full TCP communication, subsequently, is less efficient than the previous SYN scan.

  - UDP Scan `-sU`
    nmap is able to use UDP scan to discover services (as well as identify/enumerate) that runs on UDP (i.e.: DNS,SNMP,DHCP) commonly used to exploit systems.

    In many instances, auditors will overlook the existence of UDP services. To make matters worse, network administrators often times leave them accessible.

    It is important to know that, given the design of the protocol, UDP scans are much slower and more difficult to conduct. (But it should always be done!)

    This is how it works:
    - nmap  start the UDP connection by sending a packet to the remote host
    - Since the port is open, the host responds to our request. Right after, the remote host closes the connection by sending an ICMP packet *Destination Unreachable*
    - In contrast, when the port is closed, an ICMP packet *Destination Unreachable* will be sent right away (without the first response)

  - Idle Scan `-sI` ([More](http://nmap.org/book/idlescan.html))
    Idle scan is a stealth technique that involves the presence of a zombie in the target network. A zombie is a host that is not sending or receiving any packets thus, the reason its called an idle scan.

    In order to understand this technique, you need to know that the IP protocol implements a [Fragmentation ID header](https://tools.ietf.org/html/rfc791) and that many OS increase its value by 1 (for each packet)

    **Fragmentation**
      If a message (package) is too large, a message must be split into smaller messages. In essence, this is the process of fragmentation.

      When a device sends fragments of a message, the host on the other side must be able to identify these fragments in order to reassemble them.

      This is achieved by assigning an unique identifier to each fragment of the message called **Fragmentation ID**. This way the receiver knows the correct sequence of the fragments and can assemble them back into the original message.

    By probing the fragmentation ID's on the zombie, we can infer if a port is either open or closed on our target. But, there are 2 prerequisites that must be met:
    1. Find a zombie that assigns IP ID both incrementally and globally
    2. Find an idle zombie, meaning that there should be no other traffic on the zombie that will disturb the IP ID

    How do we determine a good candidate zombie?
      We can use nmap to perform OS fingerprinting on potential candidate zombies.
      If we run this scan with the verbose mode enabled, nmap will determine if the IP ID sequence generation is incremental (the one we need).

      The command is as follows:
      ```
      nmap -O -v [IP_ADDRESS]
      ```
      If the IP ID Sequence is incremental,
      it will output `IP ID Sequence Generation: Incremental`

    Before seeing the attack in detail, let's take a look at the steps required to mount it:
      1. Probe the zombie's IP ID and record its value
      2. Forge a SYN packet with the source address of the zombie and send it to the port of our target host
          Depending on how the target reacts, it may or may not cause the zombie IP ID to be incremented
      3. Probe the zombie's IP ID again and, pending upon the ID we can infer if the target port is opened or closed

    Lets now take a look at all the tasks that we (the attackers) have to perform once we discover a zombie:
      1. Probe the zombie's IP IS by sending a SYN/ACK to it
      2. Since the communication is not expected, the zombie will send back a RST with its IP ID
      3. Forge a SYN packets (IP spoofing) with the zombie source IP address and send it to the target we wish to scan

      The results depends on whether the port is opened or closed
    - If the port is open
      4. The target send back a SYN/ACK to the zombie
      5. The zombie does not expect it, therefore it sends an RST back to the target and increments its IP ID
      6. The attacker probes again the zombie's IP ID
      7. The zombie sends back a RST. The attacker sees that the IP ID is incremented by *2* (from initial probe)
    - If the port is closed
      4. The target send back to the zombie a RST and the zombie simply ignores the packet leaving its IP ID intact
      5. The attacker probes again the zombie's IP ID
      6. The zombie sends back a RST and the attacker sees that the IP ID is incremented only by *1*

    Now that we know how this technique work, we will see how to run it using nmap `-sI` option.
      We need to use an open port on the zombie, which in our case, is port 135:
        ```
        nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -v
        ```
        or
        ```
        nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p23 -v
        ```
        or
        ```
        nmap -Pn -sI 10.50.97.10:135 10.50.96.110 -p- -v
        ```
        Description:
        - `10.50.97.10:135` is the zombie IP and port
        - `10.50.96.110` is the target we wish to scan
        - `-Pn` prevents pings from the original (our) IP
        - `-v` sets the nmap verbosity
        - `-p` port to scan (`-p-` means all port, not specified means the default port)

      If we inspect the traffic with Wireshark, we will not see any communication between the target host and out original IP addresses!

      You can see a detailed list of every packet sent and received with nmap by using the `--packet-trace` option

  - Never do DNS resolution `-n`
    This is an additional flag we can add to our nmap scans to increase our scan times, and also help us stay a bit more "under the radar", as reverse DNS lookups can generate more noise than necessary.

  - FTP Bounce Scan `-b`
    This is another stealthy scan option we can use.
    Also known as [FTP Bounce Attack](https://en.wikipedia.org/wiki/FTP_bounce_attack), this type of scan exploits an FTP servers' `PORT` command and if an FTP server is vulnerable, allows us to launch port scans from the FTP server to other machines on the internet, or to even conduct scans against machines we don't have direct access to on an internal network.

    All scans using this method will appear to have originated from the FTP server, and is another great way to hide our true source.

  - TCP NULL `-sN`, FIN `-sF`, Xmas scans `-sX`
    These scans exploits a loophole in the [TCP RFC](http://www.rfc-editor.org/rfc/rfc793.txt) in order to differentiate between open and closed ports.

    We must keep in mind that a TCP packet can be tagged with six different flags (Synchronize (SYN), Finish (FIN), Acknowledgement (ACK), Push (PSH), Reset (RST), and Urgent (URG)).

    Basically, the TCP RFC states that if a destination port is closed, an incoming packet segment not containing a Reset (RST), causes a Reset to be sent (as the response).

    The RFC goes on and states that packets sent to open ports without the SYN, RST, or ACK bits set, should be dropped and the packet should be returned.

    As a result, if a system compliant with the TCP RFC receives a packet that does not contain the required bits (SYN, RST, ACK), it will return:
    - **an RST if the port is closed**
    - **no response if the port is open**

    Moreover, as long as none of those three required bits are included (SYN, RST, ACK), any combination of other bits (FIN, PSH, URG) are acceptable.

    nmap implements different scans to take advantage of this loophole:
    - Null scan `-sN` : Does not send any bits (TCP flag header is 0)
    - FIN scan `-sF` : Only sets the TCP FIN bit
    - Xmas scan `-sX` : Sets the FIN, PSH, and URG flags, lighting up the package like a christmas tree

    At one time, we could have considered these type of scans as a means to bypass firewall and packet filtering rules however, with both the proliferation of stateful firewalls, and the fact that IDS sensors are set to look for this behavior, the stealth in these techniques have been eliminated.

    Keep in mind hat many of the major OS (Microsoft Windows, Cisco IOS, IBM OS/400, Unix based) send a Reset response to the probes, regardless of whether or not the port is actually open.

    In addition, you should be aware that these scans cannot always determine if a port is *open* or *filtered*. So nmap will return a open/filtered result and you will have to test further to determine the actual state.

  - TCP ACK scan `-sA`
    This type of scan differs from the scans seen this far due to the fact that it is not used tot determine open ports.
    Instead, it is used to map out the rulesets of firewalls and determine if the devices are both stateful and which ports are filtered.

    In this particular scan, the ACK bit is the only one set. When scanning unfiltered systems, both open and closed ports will return a RST packet and nmap will remark them as *unfiltered*.

    Ports that do not respond, will then be labeled as filtered.

  - IP protocol scan `-sO`
    This scan cannot be considered a port scanning technique, as it actually just enumerated the types of IP protocols that a target system supports.

    It is similar to UDP  scan however, instead of walking through port number field of a UDP packet, it walks through the 8-bit IP protocol field.

    Rather than watching for ICMP port unreachable messages, protocols scans are on the lookout for ICMP protocol unreachable messages.

    If nmap receives any response in any protocol from the target host, nmap marks that protocol as open.

  **Output options:**
  - Normal output `-oN` : the normal output will be stored into a file
  - XML output `-oX` : creates an XML output that can be easily parsed by various tools
  - Grepable output `-oG` (Deprecated but still popular) : lists each host on one line and can be easily used to search and parse with `grep`

  GUI alternative to nmap : [Zenmap](https://nmap.org/zenmap/)

  Other features : NSE (Nmap Scripting Engine)


- Hping
  We will discuss on how to use hping to conduct *idle scan*.

  Step:
  1. Determine an open port on the host
      ```
      hping -S --scan known 10.50.97.10
      ```
  2. Find a good zombie host
      In order to estimate the host (zombie) traffic with hping, we use the following command:
      ```
      hping3 -Ss -r -p [port] [IPaddress]
      ```

      Description:
      - `-r` tells the tool to display ID increments instead of the actual ID
      - `-p` sets the destination port
        The `-r` option allows us to see the relative IP field, therefore, if the IP ID increases by 1, it can be considered a viable candidate.
        We can never be 100% sure because:
      - We have to validate if it is a global or local increase
      - Some hosts increase IP ID on a per host basis

  3. Use hping to craft packets that will be sent to target host we want to scan
      Note that these packets must have the source IP address of our zombie. Moreover, while we send out these packets ,we will also have to monitor if the zombie ID increments.

      The first command tells hping to craft a packet with the following configurations:
        ```
        hping3 -a [ZombieIP] -S -p [TargetPort] [TargetIPaddress]
        ```
      Description:
      - `-a` : source IP address (spoof with the zombie's)
      - `-S` : the packet will have the SYN flag enabled
      - `-p` : destination port

      To monitor zombie ID, we need to continue running the previous command in order to detect if it is a good zombie:
      ```
      hping3 -S -r -p 135 10.50.97.10
      ```

      If in the output the ID increment is +2, we can deduce that the *[TargetPort]* on *[TargetIPaddress]* is open.

- Other tools
  - [Angry IP Scanner](http://angryip.org/)(Linux, Windows, Mac OSX)
  - [Masscan](https://github.com/robertdavidgraham/masscan)(Linux, Windows, Mac OSX)
  - [Superscan](http://www.mcafee.com/us/downloads/free-tools/superscan.aspx)(Windows)

__________________________
## 2.3. Service and OS detection
During the previous phases, we should have gathered a list of not only alive hosts but also, information about open and closed ports for each host.

The next step is to identify which services are running on these ports. This is a very important step simply because it allows us to narrow down our attack surface. It gives us the last bit of information necessary to begin researching potential exploits on the target systems.

#### 2.3.1. Banner Grabbing
The term banner refers to the message that the service, running on the target host, sends back when another host tries to establish a connection to it. Many banners contain information such as the current version of the service (commonly default settings).

To *grab* the banner, we can use tools like [telnet](http://www.telnet.org/htm/faq.htm), [netcat](http://netcat.sourceforge.net/), or [ncat](https://nmap.org/ncat/).
These tools can be used to read and write data across networks.
In other words, they allow us to establish a connection between 2 hosts, exchange files, attach and execute applications, and much more.

For example, we can use `ncat [ipaddress] 22` to connect using SSH (port 22) to a server. The server will return a banner containing the SSH version as the result.

In a HTTP server, we will not receive an answer until we send the server some data (will be further discussed in Web App Pentesting section)

#### 2.3.2. Probing Services
You can see that we cannot solely rely on the information from banner-grabbing alone. We must leverage increasingly more accurate techniques to detect the exact version of the services running on the remote host.

To do this we can use tools such as nmap and its [service detection](https://nmap.org/book/man-version-detection.html) features. This operates differently from the banner grabbing technique used. Nmap probes the remote services, parses the responses, and then attempts to verify if there is a match within its signature database to the parsed data. By querying the services and analyzing the responses, nmap is able to determine the service protocol, the application name, the version number, hostname, and much more.

Command:
```
nmap -sV [options] [TargetIP]
```

If we want to instruct nmap to run on a specific port, we can use the `-p` option.
If we want to increase the output verbosity, we can use the `-v`.
Also notice that service detection has some specific options too:
- `-sV`: Probe open ports to determine service/version info
- `--version-intensity <level>`: 0 ~ 9 (light ~ all probes)
- `--version-light`: Limit to most likely probes (intensity 2)
- `--version-all`: Try every single probe (intensity 5)
- `--version-trace`:  Show detailed version scan activity

#### 2.3.3. OS Fingerprinting
Once we identify the services running on the remote host, we can move on and start the [OS detection](https://nmap.org/book/man-os-detection.html) phase.

There are 2 types of OS detection:
- Passive OS fingerprinting
  Identifies the remote OS with packets that are received, without sending any packets. For example: analyzing traffic that we have already captured
- Active OS fingerprinting
  Send packets and waits for response (or lack of one). Active OS fingerprinting sometimes sends unexpected packets, because different implementations respond differently to such errors.

TCP/IP fingerprinting, also known as either TCP stack fingerprinting or OS fingerprinting, is the process of determining the identity of the OS. TCP fingerprinting works by sending TCP packets to one or more ports on the target and then analyzing how the host TCP stack responds.

Many of the specifications for TCP/IP are left open to interpretation. So, each vendor implements the TCP/IP stack a bit differently therefore, creating a unique identifier/fingerprint. Nmap compares the results it obtains to its internal database of OS fingerprints and, if there is a match, prints out the detected OS.

[Here](https://nmap.org/book/osdetect.html) you can find a detailed list of techniques used by nmap, while [here](http://phrack.org/issues/54/9.html#article) you can read a good article that briefly explains these fingerprinting methodologies.

- Active OS fingerprinting
Command:
  ```
  nmap -O -n ipaddress
  ```
  It will return all possible OSes.

  You can also use `-A` to retrieve all necessary information
  ```
  nmap -A -n ipadress
  ```

- Passive OS Fingerprinting
Aside from active methods of discovering nearby hosts and OS, we also have a great tool at our disposal that allows us to conduct passive fingerprinting of hosts on a network.

This tool is known as [P0f](http://lcamtuf.coredump.cx/p0f3/) by Michal Zalewski.
You can read more about P0f at the following [link](http://lcamtuf.coredump.cx/p0f3/README)

With P0f, we can get the following information from hosts on a network without sending a single packet:
- Host uptime
- OS / software
- Distance from our current host (TTL)
- User-Agents

P0f comes preinstalled on Kali Linux, and the quickest way to get it up running is with the following command:
```
# ./p0f -i eth0
```

__________________________
## 2.4. Firewall/IDS Evasion
May of the techniques studied this far, could be detected and blocked by either firewalls or IDS's on the target network.
This causes 2 main issues:
- Becoming exposed
- Obtaining incorrect results

During the host discovery and scan phase, a number of Firewall/IDS evasion techniques must be applied if stealth is a requirement.

Tools like nmap offer options that can be used for this purpose, however, it is important to know that subverting IDS and firewall systems takes both skills and experience.

We will see some of these techniques:
- Fragmentation
- Decoys
- Timing
- Source ports

#### 2.4.1. Fragmentation
Caution: modern IDS's are able to rebuild fragmented packets, therefore, often times rendering this technique ineffective.

Nmap command:
```
nmap -sS -f targetIP
```
Description:
- `-sS` executes a SYN scan
- `-f` tells it to fragment packets

Note that fragmentation does not work very well in this type of scan:
- `-sT` (TCP connect() scan)
- `-sV` (Version detection)

Notice that instead of using `-f`, we can use `--mtu` to specify a custom offset size. It is important to know that the offset must be a multiple of 8.

#### 2.4.2. Decoys
The aim of using decoys is to add noise to the IDS by sending scans from spoofed IP addresses. As a result, a list of forged IPs (decoys) will appear on the IDS, along with the real attacker IP. This confuses the analyst watching the system, making it harder to identify the actual attacker.

In order to work, a decoy attack requires the following:
1. All decoys are up and running (otherwise, it is easy to determine the real attacker's IP)
2. The real IP address should appear in random order to the IDS (otherwise it is easy to infer the real attacker's IP)
3. ISPs traversed by spoofed traffic let the traffic go through

Using this technique, you IP will appear in the IDS alert list. However, it will be among all the decoy IP addresses. It is because of this that it will be more difficult to determine the actual system that initiated the real scan.

We can execute this scan with nmap, using the option `-D` (no spaces between IP and commas):
  ```
  nmap -sS -D [DecoyIP#1],[DecoyIP#2],[DecoyIP#3],ME [target]
  ```
  Description:
  - `ME` keyword is used to define the position of our real IP addresses among the decoys. If it is not specified, nmap will but you IP in a random position.

  You cannot use the Decoy attack with `-sT` and `-sV` scans (these use full connect scan).

#### 2.4.3. Timing
The only purpose of timing attack is to slow down the scan in order to blend with other traffic in the logs of the Firewall/IDS. It does not modify the package whatsoever.

You can define the interval between 2 scan probes, thus decreasing the chances to being noticed.

In nmap manual, this technique is not listed in the *Firewall/IDS evasion and spoofing* section, they are listed in the *timing and performance* section.
```
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds), 's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel hostscan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>
  --max-retries <tries>: Caps number of port scan probe retransmissions.
```

To perform a timing scan with nmap we can use the `-T` option in this way:
  ```
  nmap -sS -T[0~5] [target]
  ```

The following table explain differences between the 5 timing options:

| Option |  Template  | Time    |
|--------|------------|---------|
| `-T0`  | Paranoid   | 5 min   |
| `-T1`  | Sneaky     | 15 sec  |
| `-T2`  | Polite     | 0.4 sec |
| `-T3`  | Normal     | default |
| `-T4`  | Aggressive | 10 msec |
| `-T5`  | Insane     | 5 msec  |

You can also add `-p [port1],[port2],[port3]` to specify which port to scan.

#### 2.4.4. Source ports
Although this method is very simple, it can be used to abuse poorly configured firewall that allow traffic coming from certain ports.

For example, a firewall may allow only the traffic coming from specific ports, such as 53 (DNS replies) or 20 (active FTP). We can then simply change our source port in order to bypass this restriction.

Nmap allows us to fixate the source port during scans like `-sS` and `-sU`. To use this feature, we can simply leverage one of the following 2 options:
- `--source-port [portnumber]`
- `-g [portnumber]`

With the following command we run a TCP SYN scan and all the communications will be sent from port 53:
```
nmap -sS --source-port 53 [target]
```

These are just a few techniques that an attacker can use to evade Firewall/IDs detection.

You can learn more about nmap options from their [online manual](http://nmap.org/book/man-bypass-firewalls-ids.html).

__________________________
