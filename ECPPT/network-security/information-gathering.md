# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# Network Security
# Module 1 - Information Gathering

https://cdn.members.elearnsecurity.com/ptp_v5/section_2/module_1/html/index.html

__________________________
## 1.1. Information Gathering Introduction
Penetration testing must follow a methodical, organized, and controlled process
in order to both effectively review targets and keep the penetration tester
safe from consequences if issues arise.

One of the most important steps is the act of information gathering or footprinting.

The information gathering phase is focused on 2 essential aspects of all targets:
- Business
  Regarding the type of business, its stakeholders, assets, products, services,
  employees, and generally non-technical information
- Infrastructure
  Regarding the network, systems, domains, IP addresses, and so on.

We will focus on uncovering the infrastructure footprinting of the target.

At the end of the information gathering process you should at least have the
following important information about the target:

Infrastructure  | Business
----------------|---------
Network Maps    | Web presence (domains)
Network Blocks  | Physical locations
IP addresses    | Employees / Departments
Ports           | Emails
Services        | Partners and third parties
DNS             | Press / new releases
OS              | Documents
Alive machines  | Financial information
Systems         | Job postings

Information gathering techniques can be classified into 2 main disciplines:
- Active
  In this type, we gather the information about our target by directly interacting with the target system. In this phase, we gather the information about ports, services, running systems, net blocks, and so on.
  In general, active techniques can reveal the investigation to the organization through IDS or servers logs so caution should be taken to prevent this.

- Passive (OSINT / Open Source INTelligence)
  In this type, we gather the information about our target without exposing our presence.
  In this phase we not only try to gather information such as web presence, partners, financial info, and physical plants but also, infrastructure related information using publicly available resources (accessible by anyone)

Tools:
- Dradis
- Faraday
- Magitree
- Burp Suite
- Nessus
- Nexpose
- Nmap

Please make sure to read the [Methodolgy:Handling Information](https://members.elearnsecurity.com/course/resources/name/ptp_v5_section_2_module_1_attachment_eLearnSecurity_Handling_Information) guide that will teach you how to collect and store information of your target.

Parts layout:
```
                        Information Gathering
              --------------------|--------------------
          Business                               Infrastructure
      -------|-------                           -------|-------
Search Engines  Social Media           Full scope test    Narrowed Scope
```


__________________________
## 1.2. Search Engines
During the Business related information gathering phase, there is a great deal of diverse research conducted and are as follows:
```
                      -------------> Web Presence -------------
                    /                                           \
                   /                                             V  
        Cached and Archival Sites                    Partners and Third Parties
                  ^                Public Information            |
                  |                                              V  
              Harvesting                                  Job Posting
                  ^                                             /
                   \                                           /
                     ------------Financial Information <------
```

#### 1.2.1. Web Presence
In this phase, you will learn a great deal more about your target including:
- What they do
- What is their business purpose
- Physical and logical locations
- Employees and departments
- Email and contact information
- Alternative web sites and sub-domains
- Press release, news, comments, opinions

Sources that you can get the data from:
- Organization websites
  You can get:
  - The location of the company
  - The name of the business
  - Projects
  - External links (i.e. Social Media)
- Google Dorks<br>
  Operators:
  - AND
  - OR
  - +
  - -
  - ""

  Filters:
  - cache [**cache:www.website.com**]
  - link [**link:www.website.com**]
  - site [**some query string site:www.website.com**]
  - filetype [**some query string filetype:www.website.com**]

  References:
  - https://support.google.com/websearch/answer/136861?hl=en&ref_topic=3081620
  - http://www.googleguide.com/advanced_operators_reference.html
  - http://pdf.textfiles.com/security/googlehackers.pdf
  - https://www.exploit-db.com/google-hacking-database/

- Other Search Engines
  Example:
  - linkedin
  - Bing
  - Yahoo
  - Ask
  - Aol
  - Pandastats.net
  - Dogpile.com

- DUNS number and CAGE code
  Organizations that operate globally and have a desire to sell to the U.S. government or government agencies, are required to possess two codes useful to us:
  - DUNS number (Duns and Bradstreet)
  - CAGE code (or NCAGE for a non U.S. business)

  These 2 codes allows us to retrieve even more information such as contacts, products lists, active/inactive contracts with the government, and much more.

  You can retrieve the DUNS and CAGE code for a given company from the following [website](https://www.sam.gov/)

You may have probably notices by now that this process is not set in stone and is never the same for all the organizations.
Organizations belonging to different industries can be investigated through search in different publicly available databases.
Compliance and regulations might force companies to publish different kind of information publicly.

An example is publicly traded companies that have to file their financial documents to SEC database.
For this purpose, you can use the [EDGAR (Electronic Data Gathering, Analysis, and Retrieval System)](http://www.sec.gov/edgar.shtml).

#### 1.2.2. Partners and Third Parties
Other information that you can gather about the company a re mergers acquisitions, partnerships, third parties, etc.

With these you can deduce what type of technologies and systems they use internally.

#### 1.2.3. Job Posting
From job postings we can deduce internal hierarchies, vacancies, projects, responsibilities, weak departments, financed projects, technology implementations and more.

Job posts websites:
- LinkedIn
- Indeed
- Monster
- Careerbuilder
- Glassdoor
- Simplyhired
- Dice

#### 1.2.4. Financial Information
With a company's financial information, you can easily find out if the organization:
- is going to invest in a specific technology
- might be subject to a possible merge with another organization
- has critical assets and business services

Tools:
- [Crunchbase](http://www.crunchbase.com/)<br>
  You can find information about:
    - Companies
    - People
    - Investors and financial information
  Anyone can edit the information in it
- [Inc](http://www.inc.com)
Inc. focuses its attention on growing companies and provides advice, resources, and information to companies. It offers a list of the 500/5000 fastest-growing private companies, showing very useful information and statistics to them.

#### 1.2.5. Harvesting
In this phase, we unpack methods for gathering company documents such as charts (detailing the company structure), database files, diagrams, papers, documentation, spreadsheets, and so on. This is the right time to begin harvesting emails accounts (Twitter, Facebook, etc.), names, roles, and more.

It is important to know that when a document is created, it automatically stores information (metadata) like who created it, date and time of creation, software used, computer name, and so on.

If we are able to retrieve documents online and inspect the underlying metadata, we can extract useful information.

###### 1. Google Dorks
We can use this following google filters:
```
site:[website] and filetype:[filetype]
```

This will narrow down the results and display only the links to files with the `[filetype]` extension and stored in the `[website]`

###### 2. FOCA
Doing this manually can be very tedious and time consuming. A very useful tool that allows us to automatically find and download files is [FOCA](https://www.elevenpaths.com/labstools/foca/index.html)

By querying engines like google and bing, FOCA is able to retrieve files and then attempt to extract metadata such as names, usernames, passwords, OS, etc.

Note that this tool works only on Windows unfortunately.

FOCA allows us to download and extract infrastructure information as well as business information, but now we are only going to pay attention to the business information.

###### 3. theHarvester
Thanks to search engines and social networks, [theHarvester](https://github.com/laramies/theHarvester) is able to enumerate email accounts, usernames, domains, and hostnames.

Once we have the too installed on our machine, we can run the following command in order to retrieve information about elearnsecurity.com:
```
theharvester -d elearnsecurity.com -l 100 -b google
```
where:
- `-d` is the domain or the company to search
- `-l` limits the results to the value specified
- `-b` is the data sources (google, linkedin, bing, etc)


#### 1.2.6. Cached and Archival Sites
Since information on the web changes so quickly, sometimes seeking an older version of a site could provide useful to our cause.

Consider a job post. If the organization deletes it from the website, you will "lose" that information; if you could see the webpage, before the update, you could harvest that information. Turns out this is entirely possible through cache and archival technology.

Tool:
- archieve.org
- google dork (`cache:URL`)


**Remember Logging!!**
__________________________
## 1.3. Social Media
Social media is useful in the following ways:
- Learn about corporate culture, hierarchies, business processes, technologies, application
- To build a network map of people
- Select the most appropriate target for a social engineering attack

In the previous phase you should have already compiled a list of managers, employees, etc. What we have to do now is gather information on every person on this list and build the relationship among them in a company.

Tools:
- Linkedin<br>
On linkedin, you can perform advanced search functions on people based upon: current title, position, location, company and so on.

- [pipl](www.pipl.com)
- [spokeo](http://www.spokeo.com/)
- [peoplefinders](http://www.peoplefinders.com/)
- [CrunchBase](http://www.crunchbase.com/)
- Twitter
- Facebook
- Usenet<br>
Usenet is a worldwide distributed discussion system. It consists of a set of newsgroup with names that are classified hierarchically by subject.
We can also find additional information by searching for individual's name or email in Google groups.

__________________________
## 1.4. Infrastructures
The main goal of this step is to retrieve data such as:
- Domains
- Netblocks or IP addresses
- Mail servers
- ISP's used
- Any other technical information

In this process you could possibly retrieve information that is outside the *Scope of Engangement*, so be careful!

As the Scope of Engagement (SoE) for your penetration test, your customer can give you:
1. The name of the organization (full scope test)
2. IP addresses or net blocks to test

From this moment on, the approach heavily depends upon the SOE. In this section, we will assume the below listed cases:
- We have the name of the organization
- We only have specific net block(s) to test

```
                                                        ____ DNS    
                      _____________   Case 1       ____|            
                     |              Full scope         |____ IP            DNS Enum
                     |                                                     Whois
Scope of engagement -|                                                     Reverse Lookup
                     |                                  _____ Live Hosts   MSN Bing
                     |_____________    Case 2      ____|                   Further DNS
                                    Netblocks/IPs      |_____ Further DNS
```

In this process we will use the full scope engagement. This engagement is similar to how a malicious hacker would attack. Indeed the hacker only knows the target organization name at the beginning and then, he tries to derive as much information from that.

#### 1.4.1. Domains
This process aims to collect all the hostnames related to the organization and the relative IP addresses.

This process ends when we obtain the following information:
- Domains
- DNS servers in use
- Mail servers
- IP addresses

We can use a tool (webased or cl based) called [WhoIs](https://tools.ietf.org/html/rfc3912). WhoIs normally runs on TCP port 43.

Whois is a query/response protocol, widely used for querying an official domain registrar's database, in order to determine:
- The owner of a domain name
- IP address or range
- Autonomous system
- Technical contacts
- Expiration date of the domain

Note:
A Regional Internet Registry is an organization that manages resources such as IP addresses and Autonomous Systems for a specific region. There are 5 main RIR provides for WhoIs information:
- AFRINIC (Africa)
- APNIC (Asia Pacific)
- RIPE NCC (Europe)
- ARIN (North America)
- LACNIC (Latin America)

A wealth of information can be obtained from WhoIs searches that will kickstart you investigation into the right direction:
- Number Resource Records
- Network Numbers (IP Addresses) referred to as NETs
- Autonomous System Numbers referred to as ASNs
- Organization records referred to as ORGs
- Point of Contact records referred to as POCs
- Authoritative information for Autonomous System Numbers and registered outside of the RIR being queried

Note that RIRs are not responsible of the information within the databases they maintain. The responsibility for the records validity belongs to the individual organizations. They have to keep their record information accurate and up to date.

###### 1.4.1.1. DNS Records
DNS is a distributed database arranged hierarchically. Its purpose is to provide a means to use hostnames rather than IP addresses.

DNS is a key aspect of Information Security as it binds a hostname to an IP address and many protocols such as SSL are as safe as the DNS protocol they bind to.

DNS queries produce listings called Resource Records. This is a representation of Resource Records:
```
______________________________________
|         Resource Records           |
|____________________________________|
|       TTL     |   Record Class     |
|____________________________________|
|  SOA | NS | A | PTR | CNAME |  MX  |
|____________________________________|
```
- Resource Records<br>
  A Resource Records stars with a domain name, usually a fully qualified domain name. If anything other than a fully qualified domain name is used, the name of the zone the records is in will automatically be appended to the end of the name.

- TTL (Time-To-Live)<br>
  Recorded in Seconds, defaults to the minimum value determined in the Start Of Authority (SOA) record

- Record Class<br>
  Internet, Hesiod, or Chaos

- SOA (State of Authority)<br>
  Indicated the beginning of a zone and it should occur first in a zone file. There can only be one SOA record per zone. Defines certain values for the zone such as serial number and various expiration timeouts

- NS (Name Server)<br>
  Defines an authoritative name server for a zone. Defines and delegates authority to a name server for a child zone. NS Records are the glue that binds the distributed database together.

- A (Address)<br>
  Simply maps a hostname to an IP address.
  Zones with A records are called 'forward' zones.

- PTR<br>
  Maps an IP address to a hostname.
  Zones with PTR records are called 'reverse' zones.

- CNAME<br>
  Maps an alias hostname to an A record hostname.

- MX<br>
  Specifies a host that will accept email on behalf of a given host.
  The specified host has an associated priority value. A single host may have multiple MX records. The records for a specific host make up a prioritized list.

###### 1.4.1.2. DNS Enumeration
DNS lookup is the simplest query a DNS server can receive. It asks the DNS to resolve a given hostname to the corresponding IP. You can do so with `nslookup`

In order to collect the highest number of domains and subdomains related to the organization, we can use different techniques.
- DNS Lookup (and reverse DNS Lookup)<br>
  ```
  nslookup domainname.com
  ```
  or
  ```
  dig domainname.com +short
  ```
  Reverse DNS Lookup
  ```
  nslookup -type=PTR ipaddress
  ```
  or
  ```
  dig ipaddress PTR
  ```

- MX Lookup<br>
  Retrieve list of servers responsible for delivering emails for that domain.
  ```
  nslookup -type=MX domainname.com
  ```
  or
  ```
  dig domainname.com MX
  ```

- Zone Transfers<br>
  Zone transfers are usually misconfiguration of the remote DNS server. They should be enabled only for trusted IP addresses.
  When zone transfers are enabled, we can enumerate the entire DNS record for that zone. This includes all sub domains of our domain (A records)

  In order to request the entire record, we will have to ask the server that houses this records (organization's name server).
  This server can be found by executing:
  ```
  nslookup -type=NS domainname.com
  ```
  or
  ```
  dig domainname.com NS
  ```

  Then:
  ```
  >nslookup
  >server domainname.com
  >ls -d domainname.com
  ```
  or
  ```
  dig axfr @domainname.com domainname.com
  ```

#### 1.4.1.3. IP
Once we have found the number of hostnames related to t he organization, we can move on determining their IP addresses and, potentially any Netblocks associated with the organization.

Mail servers, name servers, domains, and subdomains will all be used in this phase.

Steps:
1. Resolve all hostnames we have in order to determine the IP addresses used
  ```
  nslookup ns.targetorg.com
  Server: 192.168.254.254 // DNS that will handle the query
  Address: 192.168.254.254

  Non-authoritative answer:
  Name: targetorg.com
  Address: 66.200.110.100 // IP address
  ```
2. Is this IP address hosting only that given domain?

  It is possible that more than one domain is configured on the same IP address, even if a *PTR* record is not set.
  This is a common scenario with shared hosting where hundreds of websites are configured on the same server.
  This is also typical in corporate network where multiple sub domains run on the same web server.

  For example, you have discovered that the name server of the target organization is on `66.200.110.100`. How do you determine other sub domains on the same IP?

  The first technique to try is a reverse lookup. The second is asking Google or Bing.

  `Bing` offers a query filter that returns all the websites hosted on a given IP address. We just need to use the `ip` filter, followed by the IP address of our target, e.g.:`ip: 199.193.116.231`.

  Other tools:
  - [Domain-neighbors](http://www.tcpiputils.com/domain-neighbors)
  - [Domaintools](http://reverseip.domaintools.com/)
  - [Robtex](https://www.robtex.com/)

  Repeat the process until you are satisfied with the data enumerated.
  For larger engagement, you will have to map IP addresses and related domains using mind mapping tools.

3. Who does this IP address belong to?
  - Netblock
    A netblock is a range or set of IP addresses, usually assigned to someone and has both a starting and an ending IP address. Larger netblock are given to larger organization.
    Example: `192.168.0.0-192.168.255.255`

    This netblock can also be described as follows:
    - 192.168.0.0/16 (CIDR notation)
    - 192.168.0.0 with netmask 255.255.0.0
  - Autonomous System
    An Autonomous System is made of one or more netblocks under the same administrative control. Big corporations and ISP's have an autonomous system, while smaller companies will barely have a netblock.

  You can find out the owner of a netblock or Autonomous System using WhoIs

#### 1.4.2. Networks/IPs
###### 1.4.2.1. Live Hosts
We have a list of IP addresses.
Now we need to identify which of those is alive and determine each of the role played by each IP in the target organization. For example, is it a server or a workstation?

In this early phase we do not want to enumerate the services. This will be subject of next stages.

We can:
1. Determine which IPs are alive
2. Determine if they have an associated host name/domain

By uncovering additional domains and host names associated to these IP addresses, we will gather additional information and apply the information gathering techniques on both host names and domains that we have already studied.

There are different methods that one can use to identify live hosts. The most common is the **ICMP ping sweep**. It consists of ICMP ECHO requests sent to multiple hosts.
If a given host is alive, it will return an ICMP ECHO reply.

Many tools allows us to do this:
- [fping](http://fping.org/)
- [nmap](http://nmap.org/book/man-host-discovery.html)
- hping

###### 1.4.2.2. Further DNS
This steps deals with using `nmap` to enumerate all the DNS servers that exist in the remote network. This step can be done more than once, because each time we find a new domain or a new IP, it could give us other useful information to aid us in further investigations.

In order to determine id a DNS servers are in place in a given netblock, we should first know something more about DNS. A DNS server runs on:
- TCP port 53
- UDP port 53

We can increase our surface by using nmap to scan the entire network and find hosts that we have these ports open. To do this, we can use the following two commands:
```
nmap -sS -p53 netblocksearched
```
```
nmap -sU -p53 netblocksearched
```

The first can be used to run a TCP scan, while the second can be used to run a UDP scan.

Once we retrieve more DNS servers, we can perform a reverse lookup to find out if they are serving any particular domain.

Moreover, we can try zone transfer techniques on them as well as any of the techniques studied before.

###### 1.4.2.3. Maltego
Maltego uses what it calls *transformation* to discover information about specific targets.

For instance you can begin with a server address and enumerate various information regarding that server, then build on that information until you have a full map of the entities entire internet presence.

__________________________
## 1.5. Tools
List of tools that you can use for information gathering:
- [DNSdumpster](https://dnsdumpster.com/)
- [DNSEnum](https://github.com/fwaeytens/dnsenum)
- Fierce
- [Dnsmap](https://github.com/makefu/dnsmap)
- Metagoofil
- [FOCA](https://www.elevenpaths.com/labstools/foca/index.html)
- Maltego
- Dmitry
- Recon-ng
