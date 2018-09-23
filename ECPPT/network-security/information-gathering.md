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


__________________________
## 1.3. Social Media


__________________________
## 1.4. Infrastructures


__________________________
## 1.5. Tools
