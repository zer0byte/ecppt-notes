# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
___________________________________
# Web App Security
# Module 2 - Information Gathering

https://cdn.members.elearnsecurity.com/ptp_v5/section_5/module_2/html/index.html

###### Module Map
1. Gathering Information on Your Targets
2. Infrastructure
3. Fingerprinting Frameworks and Applications
4. Fingerprinting Custom Applications
5. Enumerating Resources
6. Information Disclosure Through Misconfiguration
7. Google Hacking
8. Shodan HQ
___________________________________
## 2.1. Gathering Information on Your Targets
Information gathering is the very first and most critical step of every penetration test.

Most pentesting jobs are black-box tests.
  During a black-box test, penetration testers simulate an external hacker's attack. By design, they do not know the inner process, technology, or any other internal information. Therefore, it makes the information they discover crucial.

Gathering information about the target is the initial phase of any penetration test. You will quickly find that in general, this is the most important part of the entire engagement.
At this stage, there is not unnecessary information; everything you collect should be noted for future use. The wealth of information you collect will become useful in both understanding application logic and during the attack phase.

What sorts of information are we going after?
- Infrastructure (Web server, CMS, Database)
- Application logic
- IPs, Domains, and Subdomains
- Virtual hosts

During this chapter on information gathering techniques, you will be given valuable tips on how to store this information efficiently.

We highly recommended that you follow our approach. The better organized the information you collect, the easier it will be to find and exploit vulnerabilities.
Please refer to the methodology documents for more advice.

#### 2.1.1. Finding Owner, IP Addresses, and Emails
For simplicity, we will pretend to be unaware of what systems and individuals are behind a given website.

The first step of information gathering usually starts away from the organizations network. It begins with their electronic footprint, not just of their employees, but also of their network and websites.

Here are some tools to help you to do that.
###### 2.1.1.1. WhoIs
WhoIs lookups are used to look up domain ownership details from different databases. They were traditionally done using a command line interface, but a number of simplified web-based tools onw exist.

Web-based WhoIs clients still rely on the WhoIs protocol to connect to a WhoIs server to perform lookups and command-line execution. WhoIs clients are still widely used by system administrators.

WhoIs normally runs on TCP port 43.

###### 2.1.1.2. DNS
Now that we have some valuable information about our target, we can start digging further into the data to identify individual targets.

A valuable source for such information is the *Domain Name System* (DNS).
We can query it for some of the IP addresses that we received from the WhoIs database.

The DNS structure contains a hierarchy of names.
The root, or highest level of the system is unnamed.

**Top Level Domains** (TLDs) are divided into classes based on rules that have evolved over time. Most TLDs have been delegated to individual country managers, whose codes are assigned from a table known as ISO-3166-1. These are maintained by an agency of the UN and are called country-code Top Level Domains, or ccTLDs (ex: .us, .uk, .il, .de).

In addition, there are a limited number of "generic" Top Level Domains (gTLDs) which do not have a geographic or country designation (ex: .com, .org, .net, .gov, .edu).

Responsibility for procedures and policies for the assignment of Second Level Domains (SLDs) and lower level hierarchies of names has been delegated to TLD managers - subject to the policy guidance contained in *ISO-3166-1*.

Country code domains are organized by a manager for that country; these managers perform a public service on behalf of the Internet community.

DNS "pyramid":
- Resource Record <br>
  A Resource record starts with a domain name, usually a fully qualified domain name. If anything other than a fully qualified domain name is used, the name of the zone the record is in, will automatically be appended to the end of the name.
- TTL (Time-To-Live)<br>
  Time-To-Live (TTL), in seconds, defaults to the minimum value determined in the SOA record.
- Record Class <br>
  Internet, Hesiod, or Chaos
- SOA (State of Authority)<br>
  Indicated the beginning of a zone and it should occur first in a zone file.
  There can be only one SOA record per zone.
  It defines certain values for the zone such as a serial number and various expiration timeouts.
- NS (Name Server)<br>
  Defines an authoritative name server for a zone.
  It defines and delegates authority to a name server for a child zone.
  NS Records are the GLUE that binds the distributed database together.
- A <br>
  The A record simply maps a hostname to an IP address.
  Zones with A records are called 'forward' zones.
- PTR <br>
  The PTR records maps an IP address to a Hostname.
  Zone with PTR records are called 'reverse' zones.
- CNAME <br>
  The CNAME record maps an alias hostname to an A record hostname
- MX (Mail eXchange)<br>
  The MC record specifies a host that will accept email on behalf of a given host.
  The specifies host has an associated priority value.
  A single host may have multiple MX records.
  The records for a specific host make up a prioritized list

The DNS is a distributed database arranged hierarchically. Its purpose is to provide a layer of abstraction between Internet Services (web, email, etc.) and the numeric address (IP address) used to uniquely identify any given machine on the Internet.

This have several advantages:
- It permits the use of names instead of numbers to identify hosts (usually servers)
- Names are much easier to remember
- It permits a server to change numeric addresses without requiring notification of everyone on the Internet, by simply pointing the name to the new numeric address
- One name can refer to multiple hosts, to share the load

###### 2.1.1.3. Nslookup
`nslookup` is another very handy tool that lets you translate hostnames to IP addresses and vice versa.

Let's quickly review its main features:
- Forward Lookup <br>
  ```
  nslookup google.com
  ```
  The previous query is referred to as a lookup or as referenced in the previous section, it is an **A**.

  If you provide a domain name, DNS returns the IP addresses for the matching hosts.

- Reverse Lookup <br>
  ```
  nslookup -type=PTR 173.194.113.224
  ```
  The previous query is referred to as reverse lookup or as referenced in the previous section, it is an **PTR**.

  For reverse lookup, if you provide an IP addresses DNS returns the domain name associated with that IP.

- Records <br>
  In this step we will query the DNS server for the whole record associated with google.com:
    ```
    nslookup -querytype=ANY google.com
    ```

Every IP address on the Internet is assigned to an organization.
An organization can purchase a block of IP addresses according to their needs and it will "own" that entire block.
The **whois** database tracks the owners or public addresses as well as domain names.

Sometimes, organizations are not actually the owners of the IP addresses they use for their persistence on the internet.
They may rely on ISPs and hosting companies that lease one or more smaller netblocks (among those owned) to them.
Finding the netblock owner and the ISPs that our target organization relies on, is an important step that we will study in the next section.

**Finding Target's ISP**
  This time we want to know which ISP's hosting and IP addresses our target organization uses.

  Using `nslookup` we get the IP addresses associated to each subdomain.
  We will perform a `whois` request for each of these IP addresses to uncover the ISPs that these IP addresses belong to.

  Note: When the organization is big, net-blocks may be assigned directly to it, so no Hosting services are involved
  Note: A corporation is not limited to having only one hosting company

  Steps:
  1. The first step is to gather all the IP addresses related to a domain or subdomain. For this example we will research the statcounter.com website.
    Let's start from the domain statcounter.com:
      ```
      root@kali~# nslookup statcounter.com
      Server:       192.168.102.2
      Address:      192.168.102.2#53

      Non-authoritative answer:
      Name:    statcounter.com
      Address: 104.20.2.47
      Name:    statcounter.com
      Address: 104.20.3.47
      ```

      As you can see, there are 2 IP addresses (**A** records in the DNS) registered for that domain. We will store these 2 IP addresses for steps 3 and 4 of this process.

  2. Continuing to perform a per-subdomain IP survey, we move on to www.statcounter.com and find out that it has different IP addresses associated with it.
    ```
    nslookup www.statcounter.com
    ```
    This command returns other two IP addresses:
    - `93.188.134.172`
    - `93.188.134.237`

    The returned IP addresses must be saved for further checks against `whois`.

  3. We can continue this survey against all the organization's domains and subdomains, but we will stop here and start our ISP recognition phase.
    We have to check:
    1. `104.2.47`
    2. `104.3.47`
    3. `93.188.134.172`
    4. `93.188.134.237`

  4. Using online tools such as [arin.net](http://whois.arin.net/rest/net/NET-108-162-192-0-1/pft), [whois.domaintools.com](http://whois.domaintools.com/), or [ripe.net](https://apps.db.ripe.net/search/query.html) we will uncover the ISPs that our organization relies upon.

    Let's start querying `104.20.2.47`.
      This IP address belongs to **CloudFlare**. (see img-50)
      A netblock for this ISP is `104.16.0.0/12`

    We can move on with the other 2 IP address `93.188.134.172` and `93.188.134.23`:
      We have now uncovered that the www.statcounter.com subdomain is handled by another organization *CDNetworks* (see img-51)

  At the end of this process, we can build a table with all the IP addresses used by the organization and the ISP/Hosting services that these IP addresses belong to.
  To perform a thorough pentest, this information must be included in your penetration testing documentation.
  This information will become useful when mapping the attack surface.

**Finding Target's ISP with Netcraft**
  A faster way to uncover the organization's hosting scheme and ownership is by using **Netcraft**.
  Netcraft has a wealth of information for us and we will use it often in this module.

  Visiting `www.netcraft.com` and doing a search for statcounter.com will reveal the Hosting provider for statcounter.com as well as its IP netblock.

  The statcounter.com example is a good example for demonstrating how an organization may rely upon different netblock (and hosting) for different servers.

  By just querying a domain we get all the information in 1 page.

  Let us try it by visiting `netcraft.com`. (see img-55-56)

  If your read and applied our methodological approach, this map should be similar to the one you created up to this point (see img-57)

___________________________________
## 2.2. Infrastructure
The infrastructure behind a web application is what support it and allows it to function.
This includes the web server that is directly involved in the execution of any web application.
The 2 most common web servers used on the internet today are *Apache* and *Microsoft IIS*.

Discovering what kind of web server is behind your application will give you a hint about what OS the server is running. This helps you to research what known vulnerabilities may exist.

  For example, discovering [IIS](http://www.iis.net/) (Internet Information Service) web server will tip us off that the server is running an OS in the Windows Server OS family.

  IIS version 6.0 is installed by default on all Windows Server 2003 boxes, Windows Server 2008 supports IIS 7 and Windows server 2012 is the only one to support IIS 8.0

These guesses are correct in 90% of the cases when dealing with IIS and Windows Server however, the same cannot be said for many different Linux and BSD distributions. These may run different versions of Apache web server.

Although hacking into the server OS is beyond the scope of our web application test engagement, having a clear understanding of the infrastructure will be useful in the next testing steps.

#### 2.2.1. Fingerprinting the Webserver
Uncovering both the web server type and version will give us enough information to mount many different attacks against its components (during later stages of the test).

IIS components, usually called ISAPI extensions, works as dynamic libraries, extending the functionalities of the web server and performing different tasks for the web server.
These include: URL rewriting, load balancing, script engines (like PHP, Python, or Perl), and many others.

  A rewriter changes "ugly" web application URLs such as `news.php?id=12` to a more search-engine-friendly URL like `news/12.html` or a route like `news/12`

  Also an IDS is a web application firewall that detects and prevents intrusions coming from the HTTP/S protocol.

The presence of either of these 2 modules can alter the results of our tests significantly, so performing a careful fingerprint of the web server and its components is obviously a great help.

Let's have a look at the first and simplest way to retrieve the web server version along with other useful information.
  Sometimes, this information is leaked through the HTTP headers in response to a trivial HTTP request to the web server.
    **Request**
    ```
    GET / HTTP/1.1
    Host: test.xxx
    ```
    **Response**
    ```
    HTTP/1.x 200 OK
    Date: Sat, 18 Apr 2009
    13:08:40 GMT
    Server: Apache
    Content-Length: 88750
    ```
    As we can see from this response, the web server has quietly provided its name to us!
  In this case unfortunately, we have no versioning information.
  That info is extremely important to us in order to understand the level of exposure to known vulnerabilities.

For the version info, we can use Netcraft; it provides web server analysis via its enormous information database.
  It can be reached at www.netcraft.com

  You will find Netcraft to be very useful not only for this web server fingerprinting step but also, for subsequent steps like collecting all available subdomains for a domain.

  Let's try our web server identification using Netcraft.

  By searching for the domain name from the Netcraft home page, we are presented with a great deal of information regarding our target.
  This includes the web server version, name server, and IP addresses of different web servers in use.

  The Netcraft site report also shows the webserver and historical OS information about the domain microsoft.com.

  We searched for domain info on microsoft.com and Netcraft responded with a Web Server version *Microsoft-IIS/8.5*.

  We are also given a list of the web servers and IP addresses.
  Microsoft uses a server farm and the HTTP request may be routed to different web servers based on load and availability at the moment we visit.

    This is not to confuse us, but it must be taken into account when we perform our web application tests.

    It is not uncommon to find corporations or even small businesses using load balancers that route HTTP request to different servers that may even run different web servers versions.

    The advice here is to take note of all web servers version-to-IP couplets for further use.

    The Nameserver is the DNS server that replies to all lookup queries regarding the namespace of a domain. An `nslookup` query for microsoft.com involves a request to ns1.msft.net for example:
      ```
      C:\>nslookup -type=NS microsoft
      Server:   google-public-dns-a.google.com
      Address:  8.8.8.8

      Non-authoritative answer:
      microsoft.com   nameserver = ns3.msft.net
      microsoft.com   nameserver = ns4.msft.net
      microsoft.com   nameserver = ns1.msft.net
      microsoft.com   nameserver = ns2.msft.net
      ```

In addition to the web server version, IP addresses, and nameservers, netcraft provides the following information we can capture:
- Server version
- Uptime stats
- IP address owner
- Host provider

Sometimes netcraft does not provide us with enough information regarding our target web server version.
In addition, there are cases where netcraft cannot be used, such as with Internal Web Servers that are not attached to the Internet.

When this is the case we can use manual testing techniques and tools to identify a server such as `netcat`, `httprint`, [whatweb][https://github.com/urbanadventurer/WhatWeb], and [wappalyzer](https://wappalyzer.com/).

  Some of these freely available tools rely on common web server characteristics in order to accurately identify them.

  They probe the web server with a series of requests and compare the responses to their database of signatures in order to both find a match, and accurately guess the following information:
  - Web server version
  - Installed modules
  - Web enabled devices (routers, cable modems, etc.)

  The most important feature of these tools is that they do not solely rely on the service banner.

  They are capable of fingerprinting the web server version even when the banner of the HTTP response header has been manually obfuscated/altered using security modules ([mod_security](https://www.modsecurity.org/))

###### 2.2.1.1. netcat
The first one we want to use for manual fingerprinting is `netcat`.
This is a simple utility that reads and writes data across network connections.

By using `netcat`, we can establish a connection to the Web Server and look at the Server field in the HTTP response header.

The following is an example of what we can get by using `nc` (netcat) against a Web Server that resides in our network:
  ```
  root@kali:~# nc 192.168.102.136 80
  HEAD / HTTP/1.0

  HTTP/1.1 200 OK
  Date: Mon, 30 Mar 2015 14:40:06 GMT
  Server: Apache/2.2.22 (Debian)                  // The server is Apache
  Last-Modified: Thu, 05 Feb 2015 21:12:05 GMT
  ETag: "1847cb-b1-50e5dc184b340"
  Accept-Ranges: bytes
  Content-Length: 177
  Vary: Accept-Encoding
  Connection: close
  Content-Type: text/html
  ```

Here is another Web Server address. As you can see, the field order changes as well as their values:
  ```
  root@kali:~# nc 134.170.185.46 80
  HEAD / HTTP/1.0

  HTTP/1.1 301 Moved Permanently
  Cache-Control: private
  Content-Length: 177
  Content-Type: text/html
  Location: http://www.microsoft.com
  Server: Microsoft-IIS/8.5                   // The server is Microsoft IIS
  Set-Cookie:
  ...
  ```

Beyond the Server header we should also look at the **X-Powered-By** header, which may reveal the technology behind the Web Application:
  ```
  root@kali:~# nc 134.170.185.46 80
  HEAD / HTTP/1.0

  HTTP/1.1 301 Moved Permanently
  ..stripped output..
  Server: Microsoft-IIS/8.5
  X-Powered-By: ASP.NET                        // Web App is using ASP
  X-UA-Compatible: IE=EmulateIE7
  Date: Tue, 31 Mar 2015 07:48:01 GMT
  Connection: close
  ...
  ```

Cookies are also an interesting resource that may reveal useful information in this phase. Each technology has its default cookies names. Therefore, we can potentially guess the web server by inspecting the cookie header. Here is a short list of what you may encounter.
  | Server | Cookie                  |
  |--------|-------------------------|
  | PHP    | `PHPSESSID=XXXXX`       |
  | .NET   | `ASPSESSIONIDYYY=XXXXX` |
  | JAVA   | `JSESSION=XXXXX`        |

As you can imagine, there may be different result output depending on the service running on the machine, the version, OS, and so on.

[Here](https://www.owasp.org/index.php/Testing_for_Web_Application_Fingerprint_(OWASP-IG-004)) and [here](https://www.owasp.org/index.php/Fingerprint_Web_Application_Framework_(OTG-INFO-008)) you can find a few more examples and information about different Web Server outputs.

###### 2.2.1.2. WahtWeb
Another very useful tools is [WhatWeb](https://github.com/urbanadventurer/WhatWeb). It is a command line tool that can be used to recognize website technologies, Web server versions, blogging platforms, JS libraries, and much more.

Pentesting distributions such as Kali Linux have it installed by default, so you can start using it by running the following command:
  ```
  root@kali:~# whatweb -h
  ```

  If you are using a clean environment, you can use `git clone` to download it on your machine.

This tool is very easy to use. You only need to type the name of the tool followed by the address (IP or URL) of the target and hit enter. Note that you can specify multiple targets in the command or even IP ranges.

Moreover, it offers options that allows us to specify different user agents, HTTP basic authentication credentials, cookies, proxy, and much more.

Let us try to run the tool against www.elearnsecurity.com (see img-88)

  As you can see, we have a great deal of information in the output. Moreover, you should notice that the tool automatically follow redirections (302): in the output we have the results for both HTTP and HTTPS websites.

The previous output may seem a bit messy.
  If you want a more readable output, use the `-v` option.
  As you can see (see img-90), we now have all the information well organized.

###### 2.2.1.3. Wappalyzer
As we have seen, WhatWeb successfully identified the target Web Server.
Although we are not going to inspect all the tool options, feel free to explore.

Instead we are going to see another very useful tool that can be used directly from our web browser. It is called [wappalyzer](https://wappalyzer.com/download) and it is a Web Browser plugin based tool that works both on Firefox and Chrome.

Once you install the plugin from the previous link, you have to navigate to your target website: you will see some icons in your address bar.

Each icon gives you information about the Web Server, such as the OS, the Web Server, JavaScript frameworks, and much more.

In order to inspect the information found, just click on an icon and a pop up will appear on the right, listing all the information gathered.

(see vid-94)

###### 2.2.1.4. Fingerprinting Webserver Modules

___________________________________
## 2.3. Fingerprinting Frameworks and Applications



___________________________________
## 2.4. Fingerprinting Custom Applications



___________________________________
## 2.5. Enumerating Resources



___________________________________
## 2.6. Information Disclosure Through Misconfiguration



## 2.7. Google Hacking
___________________________________



___________________________________
## 2.8. Shodan HQ
