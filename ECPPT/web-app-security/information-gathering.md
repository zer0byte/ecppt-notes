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
Along these same lines of how we fingerprinted the web server version, we can fingerprint what modules are installed and is use on the server.
Modules we are looking for are ISAPI modules (for IIS) or Apache modules that may interfere with or alter our test results.

Nowadays, more and more websites use search engine and human-friendly URLs (SEF URLs)
  So-called "ugly" URLs are the ones that carry query string parameters and values that are meaningful to the web server but not representative of the content on the page.

  For example, `www.example.com/read_doc.php?id=100` tells the server to query the database to fetch the document with `id=100`. This is not helpful to search engines looking for the document's contents.

  A search engine-friendly version would be `www.example.com/read/Buffer_Overflow.html`

So, how are the two translated?
  When a user request `read_doc.php?id=100` the server side module in charge of translating the URL will use regular expressions to match a **Rewrite rule** and will translate the URL according to the rules specified by the administrator.

  In the case above, *Buffer overflow* is the thitle field in the database at `id=100`

URL rewriting is done on Apache with the **mod_rewrite** module or **.htaccess**. On IIS it is handled by *Ionic ISAPI Rewrite* or *Helicon ISAPI Rewrite*.

The presence of URL-rewriting is easy to recognize as in the above example and should be kept in mind during the testing phase when attempting input validation attacks.

This type of attacks involves the use of malformed input (among the other data input) using the URL parameter.

Not having the real URL, and only the rewritten URL, will make it much more difficult for penetration tester to try these attacks on URLs. However, still be possible to carry malformed payload using other input *channels* such as: forms, cookies, and headers.

Search engine friendly URLs are not a security feature at all; input validation attacks are still possible if you can reverse-engineer the translation rules.
  However, there will be only rare cases in which the rewritten URL is easy to reverse engineer to its original form.
  Also note that input from forms are still intact for us to tamper with.

  ```
  Example: www.example.com/news_read/112
  ```

  We can make a guess by requesting `www.example.com/news_read.php?id=112`.
  If the two pages match and no 404 error is returned, we have found the URL rewriting rule.

  As you can see, we are guessing on the parameter name- (id), which usually does not appear in the rewritten URL.


#### 2.2.2. Enumerating Subdomains
Since we have already discussed DNS, this is the right place to mention **subdomain enumeration**.

The enumeration exercise starts by mapping all available subdomains within the domain name.

This will widen our attack surface and sometimes reveal hidden management backend panels or intranet web applications that the network administrators intended to protect through the old disgraced method of **security through obscurity**.

There are a lot of ways to enumerate subdomains:
- Netcraft
- Google
- Crawling / Brute-force
- Tools
- Zone transfers

###### 2.2.2.1. Enumerating Subdomains with Netcraft
We have already used Netcraft to gather information from a specific domain, but Netcraft can also be used to enumerate subdomains.

In order to list all the subdomains of a specific target we need to open the [Netcraft search page](http://searchdns.netcraft.com/), select *subdomain matches* from the dropdown menu and type in our string (see img-106).

If the target has any subdomain, we will see them listed on the results pages. If you want to get more information about a specific subdomain, just click on the **Site Report** icon. (see img-107)

###### 2.2.2.2. Enumerating Subdomains with Google
Although tools such as Netcraft are very useful in finding subdomains, search engines are sometimes an even better option.
We will exploit the power of [Google search operators](http://www.googleguide.com/advanced_operators_reference.html) to tweak the results and enumerate a list of subdomains.

Let us see some example that can be run with Google.
  Let us suppose our target is *microsoft.com*, and our goal is to obtain a list of all its subdomains.

  Our first search query string will be something like this:
    ```
    site:.microsoft.com
    ```
    The `site:` operator restricts the search results to the domain specified. In our case means that we will get results that have the domain *.micorsoft.com*.

    Let's see what we get.

  As we can see, each result displayed is part of the domain *microsoft.com* (see img-110)

  As you have probably noticed there are some subdomains that appear more often than others (such as *www*).

Moreover, once you discover some subdomains, we have to further tweak our search query in order to delete them from the results.
  To do this we can use the minus operator (`-`) in conjunction with `site` or `inurl`:
    ```
    site:.microsoft.com -inurl:www
    ```
    or
    ```
    site:.microsoft.com -site:www.microsoft.com
    ```

  As we can see in the results, the subdomain *www* no longer appears in the output (see img-112)

Now we can continue tweaking our search query by removing the new subdomains found. So we will keep adding `-site` or `-inurl` until we find all the subdomains:
  ```
  site:microsoft.com -site:subdomain1.microsoft.com
  site:subdomain2.microsoft.com -inurl:subdomain3.microsoft.com
  ```

As you can imagine the process can be continually exhaustive, and why it is important to take good notes and use your mindmapping software.

###### 2.2.2.3. Enumerating Subdomains with Tools
In addition to the search engines, there are plenty of tools that can be used to enumerate subdomains.
Some of them parse search engines results, while others use wordlists to verify if a specific set of domains exist.

The following is a small list of these tools:
- [dnsrecon](https://github.com/darkoperator/dnsrecon)
- [subbrute](https://github.com/TheRook/subbrute)
- [fierce](https://github.com/davidpepper/fierce-domain-scanner)
- [nmap](http://nmap.org/book/man-host-discovery.html)
- [dnsenum](https://code.google.com/p/dnsenum/downloads/list)
- [knock](https://github.com/guelfoweb/knock)
- [theHarvester](https://github.com/laramies/theHarvester)
- [recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage%20Guide)


Since they are all very similar, we are going to inspect only a few (`subbrute`, `dnsrecon`, and `theHarvester`). We encourage you to try them by yourself to verify how they work and what features they offer.

**Subbrute**
The first tool, as the name suggests, uses a default wordlist to find the subdomains of a specific target. These types of tools are very useful if we cannot rely on search engines (ie: performing an internal pentest).

If you do not have the tool already installed on you machine, you can simply run the following command:
  ```
  git clone https://github.com/TheRook/subbrute.git
  ```

Once you have cloned the repository on your machine, you can launch the tool and display its options with the following command:
  ```
  python subbrute.py -h
  ```

  By running the previous command, it will show that it uses a default wordlist named `names.txt`

Let's try to run the tool and see what subdomains it is able to enumerate. We are not going to use any particular options this time. (see img-119)
  ```
  root@kali:~#python subbrute.py microsoft.com
  microsoft.com
  www.microsoft.com
  home.microsoft.com
  cs.microsoft.com
  members.microsoft.com
  blogs.microsoft.com
  ...
  ```

As shown in the previous screenshot, by simply running the tools against the *microsoft.com* domain, it is able to enumerate an acceptable number of subdomains.

In case you want to use a custom wordlist you can simply run the following command:
  ```
  python subbrute.py -h -s [path_to_file.txt]
  ```

**dnsrecon**
It comes pre-installed on Kali Linux. You can get the help menu with the following command:
  ```
  dnsrecon -h
  ```

Similarly to `subbrute`, `dnsrecon` can leverage wordlists to enumerate subdomains. However, in addition to this, it also offers the possibility to use search engines like google.

The option we are interested in is `-g`: *perform Google enumeration with standard enumeration*. Moreover, it is multi-threaded, so we can speed up the process by setting more threads (`--threads`). Let us use *microsoft.com* once again and run the following command:
  ```
  dnsrecon -d microsoft.com -g
  ```

  As you can see in the output (see img-123), first, it executes some general enumeration by checking the DNS configuration and then begins enumerating the domains via Google.

**theHarvester**
`theHarvester` is a tool for gathering subdomains names from different public sources such as search engines or PGP key servers. Among its subdomain enumeration features, theHarvester is also able to retrieve data related to the target organizations from many websites such as *Linkedin*, *People123*, *Twitter*, *Google+*, and few more.

Kali Linux already has `theHarvester` installed by default.
We can simply run it as follows:
  ```
  theharvester [options]
  ```
  Options:
  - `-d`: Domain to search
  - `-l`: Limit the results to work with
  - `-b`: Data source (bing, google, linkedin, pgp, all,...)
  - `-f`: Output to HTML or XML file (optional - good for long lists)

Now that we know its basic operations, let's try to run the tools against *microsoft.com*. We will use google as the search engine, we will limit the results to 200, and also store the results into a HTML file.

Our command will look like this (see img-127):
  ```
  theharvester -d microsoft.com -b google -l 200 -f /root/Desktop/msresults.html
  ```

Another very useful feature of theHarvester, is the ability to collect data from other sources, such as Linkedin. Obviously, in order to list all the people that are somehow related to our target.
  For example, let us see what happens if we use the target *elearnsecurity*:
    ```
    theharvester -d elearnsecurity.com -b linkedin -l 200
    ```

  We will obtain somethings like the following screenshot (see img-129).
  All the people listed here are related to *elearnsecurity* (employees, customers, partner, and so on)


###### 2.2.2.4. Enumerating Subdomains with Zone Transfers
In addition to search engines and tools, there are other ways  we can discover information about domains and subdomains.

One of these is through a [Zone Transfer](https://en.wikipedia.org/wiki/DNS_zone_transfer)

  Zone transfer is the term used to refer to the process by which the contents of a DNS Zone file are copied from a primary DNS Server to a secondary DNS Server.

  Zone transfers are usually the result of a misconfiguration of the remote DNS server. They should be enabled (if required) only for trusted IP addresses.

  When zone transfers are available, we can enumerate all of the DNS records for that zone. This includes all the subdomains of our domain (A records).

On Windows systems, we can gather information from Zone Transfer by running the following commands: (output: see img-133)
  ```
  nslookup
  server [NAMESERVER FOR mydomain.com]
  ls -d mydomain.com
  ```
  You can find the `[NAMESERVER]` by just doing:
    ```
    nslookup -type=NS mydomain.com
    ```

On Linux systems you can run the following command: (output: see img-135)
  ```
  dig @nameserver axfr mydomain.com
  ```

#### 2.2.3. Finding Virtual Hosts
A virtual host is simply a website that shares an IP address with one or more other virtual hosts.
These hosts are domains and subdomains.
This is very common in a shared hosting environment where a multitude of websites share the same server/IP address.

For example:
  There are multiple virtual hosts associated with the IP address `192.168.3.2`:
  - www.foo.com
  - mail.foo.com
  - admin.foo.com
  - extranet.foo.com

Many of the tools we have seen previously for enumerating subdomains can also be used in finding virtual hosts. The following is an example of what the tool **fierce** is able to discover starting from the domain *elearnsecurity.com* (output see img-139)

**Remember to update your map with the latest information!**

___________________________________
## 2.3. Fingerprinting Frameworks and Applications
Once we have a list of subdomains, we will apply the techniques that follow in this module to all of them.

We will basically start looking at the webpages running on each of the subdomains we have domains.

Common applications are software that is available for anyone to use (aka COTS - Common off the shelf).

They can be either open source or commercial, but what makes them interesting for our analysis is the fact that we have access to their source code (and other security researchers may have looked at it before us)

We are able to read both the application logic and the security controls implemented (or not implemented) therefore, we gain a big advantage over applications built in-house.
For a pentester, the logic of in-house applications is a "guesstimate" task to some degree.

Common applications may be:
- forums (like phpBB, vBulletin)
- CMS's (like Joomla or Drupal)
- CRM's, blogging platforms (like WordPress or Movable types)
- Social networking scripts and a number of applications

For example, web scripts are available online at sites like http://www.hotscripts.com/

Almost all of these freely (meaning open to anyone, regardless of their price) available applications suffered from some kind of vulnerability in their history.

Understanding what piece of commonly available software the web server is running will give us the possibility for an easy exploration by just looking online for a publicly available exploit.

Even here, obtaining the name of the application will not be enough for us. We need exact version in order to look for a working exploit online.
A basic step for fingerprinting the application involves browsing the website and looking at its URLs, appearance, and logic.

Sometimes it is as easy as looking for the application's name in the web page content.
In other cases, we need to look at the web page source; the name and version is usually included in HTML comments or even in the HTTP headers.

  Sending a GET request: This is how a Joomla powered website responds to a normal GET request:
    **Request**
    ```
    GET / HTTP/1.1
    Host: www.joomla.org
    User-Agent: Mozilla/5.0 (x11; Linux x86 64; rv:31.0)
    Gecko/20100101 Firefox/31.0 Iceweasel/31.5.3
    ```
    **Response**
    ```
    HTTP/1.x 200 OK
    Content-Encoding: gzip
    Content-Type: text/html; charset=utf-8
    Server: LiteSpeed
    Vary: Accept-Encoding
    X-Content-Encoded-By: Joomla! 2.5
    ```

    As you can see, by just using telnet, Burp suite, web browsers, or any other way that will let us read the raw response, headers will reveal useful information about the website; this includes the CMS running on it: **Joomla 2.5**.

    Moreover, remember that response headers may give other valuable information such as PHP version, exact web server version, and modules installed.

  Other applications may behave differently. The HTTP header exposing the CMS version can be suppressed so we would need to move on, examining the web page content for hints.

The open source community behind these projects (but many commercial applications act similarly), usually require the final user to keep a footer notification in place that gives credit to the project for more support and acknowledgement.

  This also happens for commercial software like the famous forum application **vBulletin**; it reveals its presence both in the website title and footer:
    ```
    Copyright © 2015 vBulletin Solutions. All Rights Reserved vBulletin® is a registered trademark of vBulletin Solutions.
    ```

  Sometimes we have to look more in-depth to find what we are looking for.
  We may need to read  the web page source code and look for information in the META tags and in HTML comments. This is **WordPress**, the most popular blogging open source web application:
    ```
    <meta name="generator" content="Wordpress 4.2-beta-31946" />
    ```


**Fingerprinting Third-Party Add-Ons**
  Many different kinds of CMS's available online for free or licensed commercially.
    Very common examples of open sources CMS's are Joomla, Drupal, or Mambo.
    These have a large customer base and an ever-growing support community providing free add-ons, components, and extensions, which add more functionality to the core application.
    These add-ons are usually poorly coded and contain vulnerabilities.

  While the core parts of these projects are usually built following the best practices of secure coding, thousands of free-to-use extensions are coded by amateurs, and most of the time, these are affected by many different web application vulnerabilities.

  In the case of Joomla, (this discussion applies to many other similar projects) fingerprinting installed add-ons is as easy as looking at the website URLs:
    Joomla URLs consists of 3 main parts:
      ```
      index.php?option=%component_name%&task=%task_value%
      ```
      *index.php* is the only script you will ever see on Joomla.
      It is in charge of loading the specified components passed in, via the `option` parameter.
      More *tasks* and arguments are passed to that component with subsequent parameters.

    The following is an example of the very popular `Docman`, document manager component:
      ```
      index.php?option=com_docman&task=doc_view&gid=100
      ```
      Here we are loading the `Docman` add-on, declaring that we want to view the document with `id=100`.
      It should be clear that by looking at the `option` parameter in the URL, we can easily understand what potentially vulnerable third-party add-ons are installed and in use on the website.

  In our *Information gathering* process, we will not only list all the common applications in use, but also, all the third party add-ons in use in that application. These will likely be useful for our penetration tasks later on.

___________________________________
## 2.4. Fingerprinting Custom Applications
When you are not in front of a commonly available application, you have to go through an initial overview of the application logic.

In this case we have an in-house application, customized for the organization we are auditing. The inner logic is unknown to us but can be reverse engineered with a careful analysis of its behavior.

Our first step in this case will be to consider the overall scope of the application:
- What is it for?
- Does it allow user registration?
- Does it have an administration panel?
- Does it take input from the user?
- What kind of input?
- Does it accept file uploads?
- Does it use JavaScript, AJAX, or Flash? And so on.

These questions can be answered by just visiting the website and taking notes of anything we come across in the process.

*Spidering* (or crawling) the application is addressed at a later stage, but valuable in this case.

First, we want to understand what our application does and how it does it.

  Another important aspect to take into consideration is the possibility that we may find common software intertwined with custom code.

  Forums and blogs are great examples when we are dealing with a custom application.
    It is very likely that we find open source or commercial applications implementing blogs, forums, shopping carts, and a number of other functions.

    This applied to a small company websites as well as corporate ones. Recognizing them among the custom code is important and should be noted on our functional graph.

#### 2.4.1. Burp Target Crawler
At this point, it would be helpful to browser the application with a proxy in the middle of our requests, collecting all the headers and responses. This will help us analyze the results later.

A good recommended proxy for this stage is [Burp Proxy](http://portswigger.net/burp/download.html)
  This is the **Burp Target** tool (see img-169). Burp lets us configure our scope through simple regular expressions.

  While browsing, and if enabled, the crawler (**Spider** tab) automatically generates and records requests and response headers for further inspection. (see img-170)

  The crawler results are displayed in directories format. (see img-171)
  For each request made by the web browser (or the crawler), Burp stored the HTTP Request and Response headers.
  This will let us inspect the web application behavior carefully.

Burp is a very powerful tool.
  It lets us store all the data traveling to/from our browser while:
  - Using the crawler
  - Manually navigating the website from the web browser

  We will then be able to carefully inspect the web application.

  Your browsing of the most important parts of the target website will allow Burp to collect enough information for us to analyze.

  In this analysis phase, it may be necessary to further test the application to draw a more clear, functional graph.

  We would raw the most important parts of the entire web application.

#### 2.4.2. Creating a Functional Graph
Pentesting a complex web application is challenging as you have to keep close attention to small details while not forgetting the big picture.

The advice is to study the whole target behavior, then split the tests in smaller tasks and take care of each one.

**Study the Target**
  In this phase you would use the web browser to study the target under the behavioral point of view. No technical analysis is involved.

  The purpose of this phase is to recognize the blocks by which the target website is made of.

  The following questions should help guide you:
    - What is the purpose of the website/web application?
      - Sell online?
      - Corporate online presence?
      - Blogging?
    - What seems to be the core of the website?
      - Selling products?
      - Do they sell memberships? digital contents?
    - Does it require login to perform certain actions?
    - What are the main areas of the website?
      - Blogs?
      - eCommerce area?

  The answers to the above questions will help you illustrate the website blocks on paper.
  Make sure to use different colors for the main area of the website (*eCommerce*).
  If you find a login protected area use a rhombus.
  We have used a dark green for the HOME.

**Study the Blocks**
  Now we will repeat our process for each block more closely.

  What we want to know if:
  - Any block uses a third-party application (we will change the shape of the block if so and note the kind of application)
  - Any block can only be accessed through the login (we will create a first path using arrows)

  *eCommerce* is a green Hexagon because it is a third-party application and at the same time is the Core of the whole website (see img-182)


**Functional Graph**
  The goal of the functional graph is to visually spot important information at a glance.

  We will use this functional graph as a basis for further charting of our information and prepare it for testing part.

This step is vital and we recommend taking it seriously as it will allow you to concentrate your testing efforts on smaller parts instead of the entire application.

The ancient motto *divide et impera* (divide and conquer) is the most efficient solution when dealing with complex application.

For each smaller pat of the application, we will add notes and comments including (but not limited to):
- Client side logic (usually JavaScript code in use)
- flash applications
- cookies (a new cookie may be set when browsing this area of the website)
- authorization required
- form
- and so on

It should be clear that our attack methodology will vary depending on the data collected in this phase and, as such, the more information we retrieve from direct inspection, the greater chance we will have in identifying exploitable vulnerabilities.

#### 2.4.3. Mapping the Attack Surface
The attack surface is the area of the application in which we will focus all of our security testing efforts.
  The more we know about our target web application, the wider the attack surface will be.
  Use the suggested graphing techniques or create one you are comfortable with and stick with it.

  In our previous step, we dissected the application into smaller blocks, noting its most important functionalities and features:
  - Client Side Validation
  - Database Interaction
  - File Uploading and Downloading
  - Display Of User Supplied Data
  - Redirection
  - Access Controls and Login Protected Pages
  - Error Messages
  - Charting

  Going deeper into this process, we will have to add more detailed information that will serve as a checklist in our testing phase.

  We will collect this information on a per-block basis.
  A suggested graph is given in the image (see img-189).
  An alternative is given in the Charting tab. We will inspect it later on.

Let's begin mapping the attack surface:
1. Client Side Validation
User submitted data through web forms can be validated on the client side, server side, or both.

Recognizing where the validation occurs will allow us to manipulate the input order to mount our input validation attacks like *SQL Injection*, *XSS*, or general logical flaws.

We can reveal the presence of client side validation by inspecting the web page source code and looking at the JavaScript functions triggered upon form submission.

We can do this in different ways. Our favorite is **Firebug**, the very popular Firefox Add-on that lets you inspect the web page source code easily without having to read hundred lines of code before finding the interesting information.

2. Database Interaction
Detecting database interaction will allow us to look for *SQL Injection* vulnerabilities in the testing phase.

  By database interaction, we mean that the user input changes the appearance of the page because either different data is fetched from the database or new data is added.

  This hints that the SQL queries are generated from our input if the input is not properly sanitized, and may result in *SQL Injections*

It is important to note that pages that use the database in an active way.

  While you may want to skip all the pages that do not directly connect to our input, they are in fact retrieving data from the database and therefore making them important.

3. File Uploading and Downloading
It is not uncommon to encounter web pages providing dynamic downloads according to a parameter provided by the user.

  For example:
    ```
    www.example.com/download.php?file=document.pdf
    ```

This kind of behavior, if not handled correctly, can lead to a number of nasty attacks including **Remote** and **Local File Inclusion** vulnerabilities. They will be explained in the next few modules.

Note: In the phase we are not interested in direct downloads like
  ```
  www.example.com/document.pdf
  ```

File uploads forms are very common in forums, social networks, and CMSs. Desired files types can be anything from images, documents, and even executables.

Handling these uploads is a critical task for the web developer.

Mistakes in the way these documents are validated upon upload can lead to critical vulnerabilities, so we will make sure to note any page that offers this feature.

4. Display Of User Supplied Data
This is one of the most common features in a dynamic website.

Finding user supplied data will bring us to the top web application vulnerability: **Cross site scripting**

We will analyze it in depth on the next module.

5. Redirections
Redirections are server side directives to automatically forward visitor of a web page to another web page.

From the server side perspective the server can issue two different HTTP Response codes to make a redirect : *301* or *302*

  The difference between the two is not important for our analysis. We will just have to remember that *3xx* code stands for redirect.

From the client perspective, the redirection is handled by the web browser. It recognized the *3xx HTTP Response Code* and makes a request to the page contained in the *Location* header.

Example:
  **Request**
  ```
  GET /index.php?id=100
  HTTP/1.1
  Host: www.example.com
  ```
  **Response**
  ```
  HTTP/1.x 301 Moved Permanently
  Content-Length: 0
  Content-Type: text/html
  Location: http://www.example.com/index.php?=500
  ```
  The client browser will make a request to http://www.example.com/index.php?=500

Another kind of refresh is the so-called meta refresh.
The meta HTML tags are used to add metadata information to a web page. This data is usually read by search engines to better index the web page. Meta redirect, instead, is a way to generate a redirect either after *x* seconds or immediately if *x=0*
  Example:
  ```
  <meta http-equiv="Refresh" content="0; url=http://www.example.com" >
  ```

Finding redirects is an important part of our attack surface as *HTTP response splitting* and other *Head manipulation* attacks can be performed when redirects are not handled properly.

6. Access Controls and Login Protected Pages
Login pages will reveal the presence of restricted areas of the site.
We will employ authentication bypass techniques as well as password brute forcing to test the security of the authentication routines in place.

7. Error Messages
While at this stage, we will not intentionally cause the application to generate errors (we will see later how it can be a great source of information), we will collect all the errors we may encounter while browsing it.

8. Charting
We want to keep all our information well organized.
This will let us spot the attack surface and perform our tests in a much easier and scientific manner.

We advise to add the information found for each block visually like this table below (see img-208) or using a graph.

|Blocks|Client Side Validation|Redirections|Database Interaction|Errors|Displays User Data|Login|
|----------|------|------|------|------|------|------|
|Blogs     |  x   |  v   |  v   |  x   |  v   |  x   |
|e-Commerce|  v   |  x   |  v   |  x   |  x   |  v   |      
|Downloads |  x   |  x   |  v   |  x   |  x   |  v   |

You can also add more information retrieved, e.g. the URL inside the block where you encountered it.

During the process of mapping the attack surface, we have introduced 2 alternative charting techniques.
- **Tree based** chart  : especially good if there are just a few blocks. Its value is in visually spotting Information
- **Table based** chart : is what we can actually use in our testing phase, where a test for a given vulnerability will be triggered by a `V` in the table.
  For example:
    A detected interaction with a database should be tied to a test for *SQL Injection*.
    An *access restricted* page may be checked against *authentication bypass techniques*.

  This process will guarantee the best results while making sure that you do not miss any testable areas.

___________________________________
## 2.5. Enumerating Resources
The resources we are going to enumerate in this step of our information gathering process are: subdomains, website structure, hidden files, configuration files, and any additional information leaked because of misconfiguration.

This information will have to be saved, as usual, for later use (if you have not read the [Methodology document](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_1_attachment_eLearnSecurity_Handling_Information) already, this is the right time to do so).

#### 2.5.1. Crawling the Website
Crawling a website is the process of browsing a website in a methodological or automated manner to enumerate all the resources encountered along the way.

It gives us the structure of the website we are auditing and an overview of the potential attack surface for our future tests.
A crawler finds files and folders on a website because these appear in the web page links, comments, or forms.

In the section 2.4, we saw a manual, direct-browsing, crawling mechanism using **Burp Proxy**.

We can have Burp Proxy perform an automatic and exhaustive crawling of a website. This gives us the hierarchical website structure in the form of folders and files.
  To do that, the first step is to jump to the **Target** tab of **Burp** and then to the Scope subtab to set up our scope.

    This is an example of what should be inserted in the host/IP range field to retrieve data only from a given domain name: `^www\.domain\.com$` where `domain` is in our test scope.

  Once the scope has been set, we will have to make sure that the proxy is activated on port `8080`.
    To do this, we have to open the **Proxy** tab, select the **Options** subtab and make sure that the running checkbox is activated.

  At this point, we activate the crawler by going to **Spider** tab and activating the **spider is running** checkbox.

  We will set up our browser to use the proxy `127.0.0.1:8080` and navigate to the home page of the website we want to crawl.
    This should appear in the Target tab with Burp as seen in our previous tutorial on Burp Suite.

  We have 2 ways to start the actual crawling process:
  - right-click on the `host` and click `spider this host`
  - enable the spider and start browsing the web app from our browser

  We will be able to perform automatic form submission, crawling pages that are reachable only through a POST request, as well as provide login data to crawl access-restricted areas of the site.

  The ability to filter the data we receive makes sour analysis phase easier. We will be able to see only the pages with redirects, or only pages with forms, etc.

One convenience of Burp is the built-in fuzzer and HTTP request editors in the same program. By right-clicking on any crawled web page, we will be able to send it to the **Intruder-** to fuzz it, or to **Repeater-** to manually alter the request in our tests.

Although Burp may not seem so intuitive at first, it is recommended that you get familiar with this tool.
You will benefit from it in the long run.

(see vid-222)

#### 2.5.2. Finding the Hidden Files
While a crawler will only enumerate publicly available resources found through links and forums; *hidden files crawlers* and *fuzzers* like **DirBuster** will be able to find files that the web developer does not want us to see.

  For this reason, these files are the most important source of information we can find and include: backup files, configuration files, and a number of other resources that are very useful for our audit.

**DirBuster** is a mature OWASP project that allows us to crawl a website and also mount a dictionary or brute force discovery attack on the remote file system by probing each call and identifying a correct guess through the HTTP response code or web page content (in case the website uses a custom 404 page)

The tool ships with few differently-sized dictionary lists that cover the most common folder and file names.
We can choose to append an arbitrary extension to the items in the dictionary (matching the one used by our website).
  For example, if the website is using PHP files, we will use `.php` as our extension.

You can use different settings for crawling: custom user-agent, authentication, html elements to extract links from, number of requests per second, etc. (see img-227)

DirBuster will present the results as a tree of folders and files.

We need to pay particular attention to files and folders that were not  retrieved by **Burp Proxy Spider**

**Backup and Source Code File**
  Web developers are known to be lazy. They have to do their job well, but quickly. Their project time constraints often bring errors that can be fatal to the overall website security.

  Looking for backup files and source code files left on a server is an often overlooked step in the information gathering process that we will take seriously as it can give us not only useful information but also, sometimes, complete access to the organization's secrets.

  A web server is instructed to treat special file extensions as `cgi` files, where the source code is interpreted and not relayed to the client.
  When the extension is altered for back up or maintenance purposes, we are often given the application logic and if we are lucky enough, credentials to access the databases connected to that application.

  Such common, disgraced practices, involve renaming the extension in `php.bak` or `asp.bak` for example.

  In Burp, we will try to probe the web server, for every file found by our crawlers in the previous steps, for presence of back up files appending common backup extensions like `.bak` or `_bak` or `01` and so on.

  A good list of backup files extension follows:
  - `bak`
  - `bac`
  - `old`
  - `000`
  - `~`
  - `01`
  - `_bak`
  - `001`
  - `inc`
  - `Xxx`

  The extension `.inc` stands for include and it has been an abused version for a long time; in **ASP 3.0** these files were used to contain source code to be included as part of the main asp page execution.

  We recommend checking for their presence with DirBuster, especially when the site uses ASP as the server-side scripting engine.

  (see vid-233)

#### 2.5.3. Enumerating User Accounts
Among the resources we can enumerate in a website, *usernames* are another important bit of information that many turn up useful information when we have to audit an authentication mechanism.

A badly designed system can reveal sensitive information even if wrong credentials have been inserted.

For example, a web application could reveal information about the existence of a user.

It is important to note, that while determining valid *usernames* is something not considered as a serious threat, *usernames* are half of what is needed to login.

While a user, at the login stage, wants to know whether the typed username and password is wrong, applications may reveal too much information. They can make an intruder's life easier by making it possible to enumerate users.

How many times have your seen the incorrect login messages like **Login incorrect** or **Username blah does not exist**?
What is different in these messages?

Depending on the application behavior we may be able to discover valid usernames.
We will see later how to use tools such as **Burp Suite** and **Patator**, to enumerate valid usernames on the target application.

**Remember to update your map!**
___________________________________
## 2.6. Information Disclosure Through Misconfiguration
Sometimes we find that the best way to retrieve relevant information about our web applications is to look for potential mistakes in web server configuration.
A quick and very common way to gather information, files, source code, and misconfigurations is by looking for open directory listings.

#### 2.6.1. Directory Listing
These directories have been configured to show a list of the files and subdirectories in paths that we can access directly.

Note: 99% of the time, these directories have not been deliberately configured to show their content. They are just the result of misconfiguration.

(see img-241)

The previous figure shows a sample of a webserver-generated webpage showing directory listing for the main folder.

As you can imagine, you may have access to interesting information and files that potentially contain database information, login credentials, absolute server path, and so on.

Looking for directory listings is an easy task that anyone with a basic experience in scripting languages like Perl, Ruby, Python, and so on can do; and can be automated in a few minutes.

Starting with the DirBuster output, (from the previous step) which has uncovered a number of public and hidden directories on the server, let us do a **GET** request for each directory found. We will look at the web page content to search for patterns like *To parent directory*, *Directory Listing For*, *Index of* ...

If the pattern is matched, we should be in front of a directory listing we can navigate to using our web browser.

#### 2.6.2. Log and Configuration Files
**Logs** are text files left on the web server by applications to keep track of different activities: errors, logins, informative messages, and so on.

  They usually contain valuable information that we will want to uncover.

  Every web application has a configuration file placed somewhere in the application's folder structure.
  For example, *Joomla* stores the configuration file in the application root folder with the name *configuration.php*

**Configurations** files contain settings and preferences regarding the web applications installed.

  They can contain the username and password that the application uses to connect to the database, or other administrative area.

  The file in itself is not viewable because it has the *.php* extension, but we should look for backup alternatives (`configuration.php.bak`, `configuration.php.old`,...).

  In the case of Joomla and other similar CMSs, the configuration file contains the username and password of the database user used to connect to the database.

#### 2.6.3. HTTP Verbs and File Upload
Among the different mistakes an administrator can make in the configuration of the web server, leaving a directory writeable by anyone is the biggest.

Writable directories are all those directories that allow us to upload our own files on the server through the **PUT** HTTP verb.

It is worth noting that the availability of the PUT verb among the allowed verbs does not imply that we can upload files on the server.
We will be able to use the PUT verb only on writable directories.

Steps:
1. The first step in this process is to check for the availability of the PUT verb among the allowed verbs.
  To do this we will use `PuTTY` or `netcat` to query the webserver directly issuing the following request:
    ```
    OPTIONS / HTTP/1.1
    Host: targetsite.com
    ```
2. Then the server will respond with the lits of the available verbs:
    ```
    ...
    Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, ...
    ...
    ```
  We are lucky! The server allows a number of verbs.
  Note: this was an example. Usually you will find out that only **GET**, **POST**, **HEAD** and **TRACE** verbs are enabled

  Another thing to note is that if the **OPTIONS** verb is not allowed we will receive either a **4xx** or **5xx** error message according to the webserver.

This is just the beginning. We need now to know what directory, if any, we can upload to.
  It is important to understand the correlation between the directory privileges and the possibility of uploading files: if the server's local user with which the website is executed also has the write attribute enabled for a given folder, then we will be able to write to that folder.

In **IIS**, every configured website can be run by the different local users. These user are assigned to the website visitor in order for him to browse the website.
  If the user *IUSR_test* is set as the anonymous account for *test.com* then all the directories writable by *IUSR_test* will be our target (because we are indeed using *IUSR_test*'s privileges to browse the website).

Looking for writable directories is guesswork. There is not a straightforward method on how to verify directory privileges remotely.

Sometimes though, we can study the application and understand what directories are used to store user submitted avatars, files, attachments, etc. (see img-257)

  To do this, we will look for the path that brings us to these files.
    For example, in a forum, we can find the path to a user's submitted avatar. This is useful because there is a folder configured to store these files.

  Once we have a pool of candidate folders we will try our **PUT** command on:
    ```
    PUT /writable_dir/test.html HTTP/1.1
    Content-Length: 184
    <RETURN>

    [CONTENT OF TEST.HTML]
    <RETURN>
    <RETURN>

    ```
    If the upload is successful, the server will respond with a `201 Created`

    It is important to provide the `Content-Length` of the payload that we want to upload in the file specified as an argument of the **PUT**. The actual file content is in the request payload.

  To make sure that our file has been successfully uploaded to the server, we will look for it with our favorite browser.
___________________________________
## 2.7. Google Hacking
When we talk about *Google Hacking*, we mean using Google's sophisticated search operators for our information gathering purposes.

*Johnny Long* has been one of the first to uncover using Google to find misconfigured web servers, sensitive information left on the server (that crawled by Google bots), password files, log files, directory listings, and many others.

His [Google Hacking Database](https://www.exploit-db.com/google-hacking-database/) contains a list of Google searches for every purpose.

Here is and example:
  - Fingerprinting web servers is possible through Google by querying for Apache online documentation or special folder added by IIS to the web root.
  Search term:
    ```
    intitle:"Apache HTTP Server" intitle:"documentation"
    ```

  - The operator *intitle* will search only the title tag of all the pages crawled by Google. We can be more specific and restrict our search to include only our scope of audit:
  Search term:
    ```
    intitle:"Apache HTTP Server" intitle:"documentation" site:target.com
    ```

  - Looking for open directory listings containing `.bak` files is another easy task with Google:
  Search term:
    ```
    "Index of" bak
    ```
  Search term:
    ```
    "Directory listing for" bak
    ```

  - Looking for files with a specific extension is as easy as:
    ```
    filetype:bak
    ```
    or
    ```
    filetype:"inc"
    ```

  - To restrict the search only to the website in our scope add `site:target.com`
    ```
    filetype:"inc" site:target.com
    ```

Through Google Hacking, we may be able to detect:
- Error messages that may contain valuable information
- Sensitive files and directories (passwords, usernames, configs, etc.)
- Server or application vulnerabilities
- Pages that contain login portals
- and much more

[Full list][http://www.googleguide.com/advanced_operators.html] of available Google Search Operators

Google Hacking Database is available [here](https://www.exploit-db.com/google-hacking-database/)

___________________________________
## 2.8. Shodan HQ
Similar to *Google Hacking*, there is another great search engine that will be very useful for our information gathering process.

It is **Shodan HQ**. [Shodan](http://www.shodanhq.com/help/filters) is a computer search engine that uses a different approach from other search engines like Google, Yahoo, Bing, etc.
Instead of crawling data in web pages, Shodan scans the entire Internet and interrogates the ports in order to gather information from the banners.

Shodan searches includes the following protocols:
- HTTP(S)
- SSH
- SNMP
- MySQL / MondoDB
- RDP
- FTP
- Telnet
- and few more

We can use it to search for:
- devices with default username and password
- viewing the configuration of a device
- detect server versions, and much more

Like other search engines, it has Boolean operators and [filters](https:/www.shodan.io) that can be used to narrow down the results:
- **[before/after]** day/month/year : search only for data that was collected before or after the given date
- **hostname** : filters results for hosts that contain the value in their hostname
- **port** : narrow the search for specific services
- **OS** : search for specific OS

These are just a few of the available filters.

It is important to know that in order to uses most of its features (such as exporting results) and filters, you need to create an account.

Let's look at some search examples. Suppose we want to find all the devices running *apache* and that are in Italy (IT).

Our search query will be something like this: (see img-274)
  ```
  apache country:IT
  ```

  As we can see, we have a good list of matching devices. (see img-275)

If you need more detailed information about the host, you can click on *Details* and then the following page will appear. (see img-276)

Of course you can refine your searches by filtering results for specific hostname, ports, and so on.

We suggest you try it yourself in order to understand the true power of this tool.
