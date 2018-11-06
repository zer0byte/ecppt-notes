# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# Network Security
# Module 7 - Anonymity

https://cdn.members.elearnsecurity.com/ptp_v5/section_2/module_7/html/index.html

###### Module Map
1. Browsing Anonymously
2. Tunneling for Anonymity
__________________________
## 7.1. Browsing Anonymously
If you want to be anonymous, then you need to find a service that provides anonymity, as you will NOT get it for FREE.

Keep in mind that, anytime you send traffic trough another person/companies computer to hide yourself, you are exposing all data you see to that person/company as they can sniff the data. Therefore, use extreme caution and do not use any system  that you do not own, or that you do not know what information they capture.

#### 7.1.1. HTTP Proxies
Using proxies is basically asking another system to do something on your behalf. In other words, instead of sending a request directly to a web server, you would send the request to a proxy server first.

The proxy server works on your behalf to request the web page, and subsequently sends it back to you. This causes the web server to see the proxy servers address, not yours.

One of the most common types of proxies is the *HTTP* or *SOCKS* proxies.

In some instances, proxy servers will actually be chained together in order to provider further obfuscation of the original IP address.

The following is the normal flow of web requests and responses, without a proxy in between.
  1. Client makes a Request to the Web Server Requests goes to DNS for IP lookup
  2. DNS Server responds to Client with IP Address to the Web Server
  3. Client sends Request to Web Server
  4. Web server Responds to Client

The following is the normal flow web requests and responses, with a proxy in between.
  1. Client request Web Server
  2. Proxy Server requests Web Address from the DNS Server on behalf of the Client
  3. DNS Server provides the Proxy Server with the Address of the Web Server
  4. Proxy Server Sends Request to Web Server
  5. Web Server Responds to Proxy

Many times, these proxy servers can be misconfigured web servers that enabled the proxy services.

There are 2 general types of proxies:
- ones that require you to change your web browser settings in order to send requests through them,
- and others that are used through their web pages.

For proxies that require you to change your settings, you have to know the services the proxy handles and the corresponding ports. Common services:
- HTTP
- SSL/HTTPS
- FTP
- Gopher
- SOCKS

Browser like firefox allow users to set proxy addresses and ports for each of the various types.

In addition, there is a checkbox user the HTTP proxy settings that, when marked, sets the same settings for all other proxy types.

Now that we know how HTTP proxies work, let us see some examples. We will first take a look at communications without a proxy and then we will set up our machine to use one.

  First let's verify our public addresses.
    We can do this via command line tool or via web pages like:
    - http://www.whatsmyip.org/
    - http://www.checkip.org/
    - http://whatismyipaddress.com/

  Now we will visit the same site using a proxy web site.
    For our test we will use https://hide.me/en/proxy
    As you can see, the IP address is now different. This is the IP address that the web application is seeing as being us.

  Let's now see how to configure our web proxy settings in order to obtain similar results.
    The first piece of information to locate is a proxy address and port.
      There are many different sites across the internet where proxies are available.
      In our test we will use one of the proxies listed [here][https://hidemy.name/en/proxy-list/]

    Once we set the address and port, we need to open our browser connection configuration and type the address and the port in the proxy settings.

  Once we apply the settings, we can once again open one of the previous web sites and verify our IP address.
    As you can see, we have a new IP, which is again different from our real IP.

With HTTP Proxies there are several sub-types that you can encounter therefore, you should choose the type according to the level of anonymity you are looking for:
1. Highly anonymous
  These proxies do not change request fields and look like they come from a real IP
  The users real IP is hidden and there is no indication to the web server that the request is coming from a proxy.

2. Anonymous proxies
  These proxy servers also do not show your real IP address, but they do change the request fields. As a result, by analyzing the web log, it is possible to detect that a proxy server was used.

  Not that this matters however, some server admins do restrict proxy requests, so they use this type of information to block requests, such as this, in the future.

3. Transparent proxies
  Also known as HTTP relay proxies, these systems change the request fields thus, they transfer the real IP address of the user.

  In other words, these proxy systems offer no security and should never be used for security testing. The only reason to use these systems, is for network speed improvements.

In concluding the proxies section, please remember that there should only be select times that you pursue using anonymity during a test, and be sure t hat your clients are very aware of the intended methods to be used.

If you are using HTTP Proxies, be sure to select reliable proxies, preferably ones you own, or you may be exposing your customer's data to an unknown entity, for which you can be held reliable.

#### 7.1.1.1. How to Check For real Anonymous Proxies
There are many ways to tell that a proxy is a real anonymous proxy.
Much like the example above, you can use sites that display information such as IP address to check the validity of proxy servers.
There are also other tools available on the internet that can help you in ensuring you know your anonymity is protected.

First check the anonymity policy of the site you have chosen to use.
  Be sure to remember, a thief is not going to tell you they are ripping you off, so be sure you fully research the service you choose to use.

  The ultimate way to verify anonymity settings, is by visiting a site you own and verifying the visitor logs.

  A popular way to tell is also to use anonymity testing sites such as:
  - https://centalops.net/co/
  - http://www.nmonitoring.com/
  - https://pentest-tools.com/home
  - http://do-know.com/privacy-test.html
  - http://www.all-nettools.com/

  The tools-on.net website offers many excellent tools. The one we are interested in, can be found by opening *Privacy Tools* tab.

#### 7.1.1.2. HTTP_VIA / HTTP_X_FORWRDED_FOR
In HTTP client server communications, there are fields sent by the client to the server that allow the server to correctly identify certain information about the client.

Depending upon the level of proxy chosen, the information may actually reveal the true IP of the client system.

A standard HTTP communication string would look similar to the following:
  ```
  REMOTE_ADDR = 98.10.50.155
  HTTP_ACCEPT_LANGUAGE = en
  HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
  HTTP_HOST = www.elearnsecurity.com
  HTTP_VIA = not determined
  HTTP_X_FORWARD = not determined
  ```

In the example of a proxy server, the `HTTP_VIA` and the `HTTP_X_FORWARDED_FOR` fields are used by proxy systems in order to show the server that it is acting on behalf of another system.

If `HTTP_VIA` contains an address (or in case of chained proxies, many addresses), it actually indicates that there is a proxy server being used. The IP address included in this field is actually the IP address of the proxy server(s).

In contrast, the `HTTP_X_FORWARDED_FOR` field, if present, indicates the actual IP address of the client that the proxy is acting behalf of for the communication.

A simple **pass-through** or cache proxy communication string would appear as follows:
  ```
  REMOTE_ADDR = 98.10.50.155
  HTTP_ACCEPT_LANGUAGE = en
  HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
  HTTP_HOST = www.elearnsecurity.com
  HTTP_VIA = 94.86.100.1 (Squid/5.4.STABLE7)
  HTTP_X_FORWARD = 98.10.50.155
  ```

  Since we see an IP address in the last 2 fields, we know that a proxy server is used.

By analyzing either web site logs or traffic sniffing files, an administrator can easily find the proxy addresses and in turn, can use these same functions to block further access to the site.

In case of **high anonymity proxy systems** the communication would be similar to the following:
  ```
  REMOTE_ADDR = 98.89.100.1
  HTTP_ACCEPT_LANGUAGE = en
  HTTP_USER_AGENT = Mozilla/4.0 (compatible; MISE 5.0; Windows 98)
  HTTP_HOST = www.elearnsecurity.com
  HTTP_VIA = not determined
  HTTP_X_FORWARD = not determined
  ```

As you can see, this resembles the original request. The only difference is that the `REMOTE_ADDR` is actually the address of the proxy system.

If this traffic is analyzed, the administrator would have no indication that a proxy system is being used.

#### 7.1.2. TOR Network
Now that we have covered proxy systems, let us move on to more highly anonymous means of network communication called *The Onion Router* ([TOR][https://www.torproject.org/about/overview.html.en])

As stated in the Tor website,
Tor is a program you can run on your computer that helps keep you safe on the internet. It protects you by bouncing your communications around a distributed network of relays run by volunteers all around the world: It prevents somebody watching your Internet connection from learning what sites you visit, and it prevents the sites you visit from learning your physical location. This set of volunteer relays is called the *Tor network*.

The following is an example of a client operating with TOR:
- Client requests a list of TOR nodes from a directory server
- The client randomly selects nodes on the TOR network (called relays), and encrypts the traffic between each relay
- If the client requests a second destination after the specified time limit, another separate tunnel is created for that communication repeating the process

There are caveats to the TOR network in respect to the following:
TOR only works for TCP streams and can be used by any application with SOCKS support

It is highly recommended that you use protocol-specific support software, if you do not want the sites you visit to see your identifying information.

We will not dive any further into TOR, but we strongly suggest you try it by yourself.
Notice that many of the tools that you may use during your penetration tests, allow you to use TOR features. This will ensure anonymity while scanning remote sites or machines.

__________________________
## 7.2. Tunneling for Anonymity
The most effective way to achieve anonymity while conducting a penetration test is to protect your traffic either an entity or, proxy with secure protocols and encryption. This will create a secure tunnel between you and the proxy system (or entity), that cannot be easily read.

While there are many types of encrypted tunneling technologies, there are specifically 2 effective types for anonymity: SSH and IPSEC VPNs

SSH encryption offers more secure privacy and security protection than an anonymous proxy server alone.

SSH encrypts all communications to and from the client and server.
This is achieved by activating a forwarder and a listener to both send and receive the traffic.

By using port forwarding, more commonly called **SSH Tunneling**, it will create a secure connection between the local and the remote machines therefore, establishing a tunnel by which we can send unencrypted traffic securely.

Although there are different types of [port forwarding][https://help.ubuntu.com/community/SSH/OpenSSH/PortForwarding] (local, remote, dynamic), we will use the most common, **local port forwarding**

With this type of configuration, we will forward a local port on our computer in order to let the traffic pass through an SSH connection.

Suppose we want to access a machine via telnet (*homepc* on port 23), but we are attached to either a network that we do not trust, or that simply blocks telnet traffic.

  We can tunnel our telnet traffic through SSH as follows:
  ```
                                                          homepc:23
                                                              |
                                Internet                      |
                       ----------------------------       Unencrypted
                       |   ____________________   |           |
  LocalPort:3000----------|-----SSH Tunnel-----|----------SSH Server
                       |  |____________________|  |     sshserver.com
                       ----------------------------    
  ```

  The syntax of the command to run the SSH tunnel is very simple
  ```
  ssl -L [LOCAL PORT TO LISTEN ON]:[REMOTE MACHINE]:[REMOTE PORT] [USERNAME]@[SSHSERVER]
  ```

  The `LOCAL PORT TO LISTEN ON` is the port that will be open for connection to the *remote machine* (*homepc*) on the *remote post* (23). At the end of the command, we specify the *SSH server* on which tunnel the communication.


  In our previous example, we wanted to tunnel the telnet traffic from our local port 3000, to port 23 of our remote machine called *homepc*. The traffic will pass through our SSH server that is listening on *sshserver.com*

  The command start the tunnel will look like this:
    ```
    ssh -L 3000:homepc:23 root@mybox
    ```

  Once the tunnel is up and running, we will have the local port 3000 listening on our machine. We can now establish the real connection to the *homepc* telnet server with the following command:
    ```
    telnet 127.0.0.1:3000
    ```

  The traffic will automatically go through the SSH tunnel, and it will be also encrypted.

Let us use another example in order to completely understand how SSH tunneling and local port forwarding works.

  In this scenario we have 2 machines in the same network:
  - Our machine with IP *192.168.231.134*
  - SSH server machine with IP *192.168.231.135*

  As we can see in the following screenshot, the SSH server machine also offers a MySQL server, but it is configured to accept only local connections (*127.0.0.1*)

  Since we cannot establish a connection with the MySQL server from our client machine, we can use SSH tunnel to forward the connection from our machine.

  To do this we will issue the following command:
  ```
  ssh -L 3000:localhost:3306 els@192.168.231.135
  ```

  The command creates a tunnel from our local port 3000, to the localhost address on the SSH server, on port 3306 (default MySQL port).

  Once we issue the command, our machine will listen for incoming connection on port 3000. Every connection will then be forwarded to the SSH server localhost:3306.

  Indeed, if we run `mysql` on our local port, we will connect to the MySQL server running on the remote host:
    ```
    stduser@els:~$ mysql -h 127.0.0.1 -P 3000 -u root
    Welcome to the MySQL monitor. Commands end with ; or \g.
    Your MySQL connection id is 17
    Server version:5.5.5-10.1.10-MariaDB mariadb.org binary distribution

    Copyright (c) 2000, 2015, Oracle and/or its affiliates.
    ```

__________________________
