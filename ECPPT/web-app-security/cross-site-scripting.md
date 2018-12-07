# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
___________________________________
# Web App Security
# Module 3 - Cross Site Scripting

https://cdn.members.elearnsecurity.com/ptp_v5/section_5/module_3/html/index.html

###### Module Map
1. Cross Site Scripting
2. Anatomy of an XSS exploitation
3. The Three Types of XSS
4. Finding XSS
5. XSS Exploitation
6. Mitigation

___________________________________
## Introduction
Attacks triggered by user input are called input validation attacks.

  Input validation attack is when malicious input tries to subvert the anticipated function of an application because of either insufficient validation by the application or by the server, before it uses the data.

Most web application web vulnerabilities are the result of poor coding design and ignorance of the best practice of secure coding methodologies.

We will see some common mitigation techniques while studying each vulnerability.

Input validation attacks include XSS, SQL Injections, HTTP Header tampering and many others.

We will have a thorough look at each of them with their technique discovery and exploitation techniques.

___________________________________
## 2.1. Cross Site Scripting
Cross Site Scripting is one of the oldest web application attacks known, and is dated from around 1996-1998 when it was possible to control frames within a web page, through injected code, thus "crossing" the website boundaries.

Currently, it is still on top of the OWASP Top 10. This clearly goes to show how much of a threat this really is!

Cross Site Scripting is an attack in which its ultimate purpose is to inject HTML (known as HTML injection) or run code (JavaScript) in a user's Web browser.

XSS is considered an attack against the user of a vulnerable website.

The best way to introduce XSS is with this basic example.
  Consider the following PHP code:
    ```
    <?php
    echo '<h4>Hello ' . $_GET['name'] . '</h4>'
    ?>
    ```

  The above code prints a welcome message to the user whose name is retrieved from the `$_GET` variable.
    If you are not a PHP programmer, the `$_GET` variable stores the `<parameter,value>` pairs passed through the HTTP GET method.

    GET is the method used when clicking links or directly typing the website URL you want to browse, into your browser's location bar.

  The user input will be extracted from the querystring of the URL browsed (directly or by clicking on a link)
    ```
    http://victim.site/welcom.php?name=MyName
    ```
    When the above is passed to the sever, the `$_GET` variable will contain a `name` parameter with the value `MyName`.

    `?name=MyName` is called querystring

    The following HTML code will be returned from the server to the web browser:
      ```
      <h4>Hello MyName</h4>
      ```

    Our input is part of the output web page source code.

  Now let us see what happens if we submit this payload to the same page in the same parameter `name`:
    ```
    http://victim.site/welcome.php?name=</h4><script>alert('This is an XSS');</script>
    ```
    Note: the above URL should be URL-encoded
      Most browsers will do this for you.
      The URL-encoded version is the following:
        ```
        %3%2fh4%3e%3script%3ealert(%e2%80%98This+is+an+XSS%e2%80%99)%3b%3c%2fscript%3e)
        ```
  The server will run this code:
    ```
    <h4>Hello </h4><script>alert('This is an XSS');</script></h4>
    ```

The above is a fully functional XSS attack, It injects some JavaScript code into the web page source code.

The JavaScript will be executed within the website context of the browser.

This happen because the developer has forgotten to check the user input for malicious patterns.

XSS attacks are possible when the user input is used somewhere on the web application output. This lets an attacker get control over the content rendered to the application users, thus attacking the users themselves.

___________________________________
## 2.2. Anatomy of an XSS exploitation
XSS attacks can be used to achieve many goals, for example:
- Cookie stealing
- Getting complete control over a browser
- Initiating an exploitation phase against browser plugins first and then the machine
- Perform keylogging

#### How XSS exploitation works:
**Hackers Goals**: Run JavaScript to steal a session code of user X who is authenticated (logged in) on website Y

**Steps:**
1. The hacker find an XSS vulnerability affecting the website
  He will have to make sure that the Host (subdomain), in which he is looking for, matches the domain field of the cookie.

  For example:
    If the authenticated area of website *Y* is *auth.y.com*, the domain in the cookie will most likely be set to *auth.y.com*.

    He will have to find an XSS in that same subdomain.

2. Once an XSS exploit is located, he will have to:
   - build a payload
   - create a link
   - send it to the victim inviting the same to click on it (This is called Reflective XSS that we will see much more details in the next paragraphs)

    For example:
    ```
    <img src="http://auth.y.com/vuln.php?<XSS payload>">
    ```
    The image tag above may be inserted in a third-party website that the victim may trust.


We should not forget that the hacker's final goal is to have his victim's browser visit the crafted link (carrying the payload), so he will use any trick at his disposal.

We as pentesters, may want to exploit XSS found in webapps to take control of privileged accounts in order to escalate our privileges.

___________________________________
## 2.3. The Three Types of XSS
Hackers can exploit XSS vulnerabilities in many different ways.
Because of that, in this course we will use the following classification for XSS attacks:
- Reflected XSS
- Stored XSS
- DOM XSS

In the following slides you will see the difference between each attack family, then we will see how to mount and exploit an XSS attack.

**Reflected XSS**
is probably the most common and well understood form of XSS vulnerabilities.
It occurs when untrusted user data is sent to a web application and is immediately echoed back as untrusted content.

Then, as usual, the browser receives the code from the web server response and renders it.

Clearly, this type of vulnerability deals with the **server-side** code. A simple example of vulnerable PHP code is the following welcome message:
  ```
  <?php $name = @$_GET['name']; ?>
  Welcome <?=$name?>
  ```

**Persistent / Stored XSS**
are similar to Reflected XSS, however, rather than the malicious input is being directly reflected in the response, it is stored within the web application.

Once this occurs, it is then echoed somewhere else within the web application and may be available to all visitors.

Although types of XSS flaws occur within the server-side code, but, between the two, this is the most useful one for an attacker.

The reason is simple. With a page persistently affected, we are not bound by having to trick a user. We just exploit the website and then any visitor that visits will run the malicious code and be affected.

**DOM XSS**
is a form of XSS that exists only within client-side code (typically JavaScript).
Generally speaking, this vulnerability lives within the DOM environment, thus within a page's client side script itself and does not reach server-side code.

This is similar to our Reflected XSS example but without interacting with the server-side. A web application can echo the welcome message in a different way as you will be able to see in the following sample code:
  ```
  <h1 id='welcome'></h1>
  <script>
    var w = "Welcome ";
    var name = document.location.hash.substr(
               document.location.hash.search(/#w!/i)+3,
               document.location.hash.length
      );
    document.getElementById('welcome').innerHTML = w + name;
  </script>
  ```

The key to exploiting this type of XSS flaw is that the client-side script code can access the browser's DOM elements, with all the information available in it.
Example of this information include the URL, history, cookies, local storage, and many others.
Despite this, DOM is a jungle, and finding this type of XSS is not the easiest task.

Now that you have the basic classification in mind, we can dig further into each category.
#### 2.3.1. Reflected XSS
In **Reflected XSS** (or Non-persistent XSS), victims bring the payload in their HTTP request to the vulnerable website.
This payload will be inserted into the webpage and executed by their browsers.

This may sound weird but, in fact, it is not; the hacker has to trick the victim into starting a specially crafted request (clicking on a link, foe example) to the vulnerable website page in order for the attack to be successful.
When this occurs, the malicious payload is run in the victim's browser within the context of the vulnerable website.

(See img-37)

The hacker has many techniques at his disposal to camouflage the offending URL:
- [tinyurl](http://tinyurl.com/) and similar services
- iframes located in a third-party malicious page
- link in a targeted email
- and so on.

Most of the time, reflected XSS are used by hackers to steal session IDs (Stored in cookies) or the cookies themselves.
More advanced reflected XSS can be used for phishing techniques, XSS worms, or to install malware on victim's machine through the exploitation of web browser vulnerabilities.

The most naive may ask:
  Why should I do this complicated attack when I can route the user to a webpage that I own and read the cookies for `auth.y.com` from there?

  We say "run code in the website's context" on purpose.
  Only JavaScript (or Vbscript) embedded in `auth.y.com` can read cookies belonging to `auth.y.com`.

Script injected and executed in the context of the vulnerable website will allow us to read the cookie content. It will redirect the cookie content to a web page on our server that will log it for us (that is why it is called Cross Site Scripting; we are able to read content crossing the website's security boundaries).

We will see this more when we talk about Cookie stealing through XSS.



#### 2.3.2. Persistent / Stored XSS
**Persistent XSS** are attacks that lead to the execution of code in all the users web browsers visiting a vulnerable (and exploited) web page.

The injected code is saved by the application, unsanitized, and then rendered on either the same, or another web page in the same website.

The malicious code can be injected, by the attacker, directly into the web application.

This is the most important difference between **Reflected** and **Persistent XSS**.

This is the most dangerous form of XSS, as it can target all the visitors of a website, and it is the only form of XSS actually (although indirectly) targeting the website itself (not just its visitors).

A **persistent XSS** is capable of defacing a web page, altering its original appearance.
  Note: **Reflected XSS** would deface the appearance of the website only for the intended victim carrying the payload.
Such an attack is very destructive and likely to occur in: community, content drive, custom applications, like blogs, commenting systems, and social networks.

Let's see the attacking scenario of XSS.
(see img-46)
In this scenario, `page.php` has a form with 3 parameters: `Param1`, `Param2`, and `Param3`.
All of these user submitted parameters are saved in the database for later use.

One of these parameters is not sanitized for illegal characters and is prone to Persistent XSS.

The hacker constructs his exploit, carrying the XSS payload, which will be stored in the database.
The web application is designed so that `Param2`, submitted by the hacker, is displayed on `page_out.php` (once again unsanitized).

This scenario is very common and applied to a number of situations like:
- Commenting scripts
- Personal community member profiles that accept and input (these must be shown on other pages within the same website)

The outcome of this scenario is depicted in the following image
(see img-50)

By visiting `page_out.php` (the page where `Param2` is the output), all visitors of the vulnerable website execute the malicious payload that was submitted by the hacker.

Note that this type of attack is asynchronous as the exploitation and actual execution of the code happens at different times.

During a reflected XSS attack:
- the user could defend himself at some extent relying upon his experience and security awareness

However, in this case (Persistent XSS):
- the attack is so covert and neat, that as soon as the user browses the infected page, the code is automactically executed.


#### 2.3.3. DOM XSS



___________________________________
## 2.4. Finding XSS


___________________________________
## 2.5. XSS Exploitation


___________________________________
## 2.6. Mitigation
