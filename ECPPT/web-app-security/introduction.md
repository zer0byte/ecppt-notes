# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
___________________________________
# Web App Security
# Module 1 - Introduction

https://cdn.members.elearnsecurity.com/ptp_v5/section_5/module_1/html/index.html

###### Module Map
1. HTTP/S Protocol Basics
2. Encoding
3. Same Origin
4. Cookies
5. Session
6. Web Application Proxies
___________________________________
## 1.1. HTTP/S Protocol Basics
HTTP is the basic protocol used for web browsing and these days, for almost all communication on the web.

It is the client-server protocol used to transfer web pages and web application data.
The client is usually a web browser that starts a connection to a web server such as an **MS IIS** or **Apache HTTP Server**.

During an HTTP communication, the client and the server exchange messages. The client sends a request to the server and gets back a response. The format of an HTTP message is:
  ```
  HEADERS\r\n
  \r\n

  MESSAGE BODY\r\n
  ```

#### 1.1.1. HTTP Request
The following is the content of the request header that we send when we open our web browser and navigate to *www.google.com*:
  ```
  GET / HTTP/1.1
  Host: www.google.com
  User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0
  Accept: text/html,application/xhtml_xml
  Accept-Encoding: gzip, deflate
  Connection: keep-alive
  ```
  Description:
  - `GET / HTTP/1.1` : `VERB PATH PROTOCOL`
  - `Host: www.google.com` : website name
  - `User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0` : browser version
  - `Accept: text/html,application/xhtml_xml` : Document type expected to be returned
  - `Accept-Encoding: gzip, deflate` : Encoding type expected to be returned
  - `Connection: keep-alive` : Keep connection alive for an unspecified amount of time

#### 1.1.2. HTTP Response
Now that we know how the request is composed, let's inspect the web server response.

In the response to the HTTP Request, the web server will respond with the requested resource, preceded by a bunch of new *Headers*.
These new headers from the server will be used by your web browser to interpret the content contained in the response content.

Below is an example of a web server response
  ```
  HTTP/1.1 200 OK
  Date: Fri, 13 Mar 2015 11:26:05 GMT
  Cache-Control: private, max-age=0
  Content-Type: text/html; charset=UTF-8
  Content-Encoding: gzip
  Server: gws
  Content-Lenth: 258

  <PAGE CONTENT>
  ```
  Description:
  - `HTTP/1.1 200 OK` : Status line (`PROTOCOL STATUS_CODE STATUS_TEXT`)
  - `Date: Fri, 13 Mar 2015 11:26:05 GMT` : Date
  - `Cache-Control: private, max-age=0` : Agree about caching rules
  - `Content-Type: text/html; charset=UTF-8` : Let's the client know how to interpret the body of the message
  - `Content-Encoding: gzip` : extends Content-Type (In this case the body is compressed)
  - `Server: gws` : Web server banner (In this case Google Web Server)
  - `Content-Lenth: 258` : Content length in bytes

#### 1.1.3. HTTP Header Field Definitions
If you want to dig deeper into the syntax and semantics of all standard HTTP/1.1 header fields, please check the following [RFC 2616](http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.1). It lists and explains all the header fields in detail.

Use Google Chrome's or Firefox's developer traffic inspection tools to better learn HTTP headers.

#### 1.1.4. HTTPS
HTTP content, as in every clear-text protocol, can be easily intercepted or mangled by an attacker on the way to its destination. Moreover, HTTP does not provide strong authentication between the two communicating parties.

In the following sections you will see how to protect HTTP by means of an encryption layer.

HTTP Secure (HTTPS) or HTTP over SSL/TLS is a methods to run HTTP, which is a clear-text protocol, over SSL/TLS, a cryptographic protocol.
In other words. when using HTTPS:
- An attacker on the path cannot sniff the application layer communication
- An attacker on the path cannot alter the application layer data
- The client can tell the real identity of the server and, sometimes, vice-versa

HTTPS does not protect against web application flaws!
  All the attacks against an application happen regardless of SSL/TLS.

  The extra encryption layer protects data exchanged between the client and the server. It does not protect from an attack against the application itself .

  Attacks such as XSS and SQL injections will still work.
  Understanding how HTTP and web applications work is fundamental to mount both stealthy and effective attacks.

___________________________________
## 1.2. Encoding
Information encoding is a critical component of information technology. Its main function is to represent the low-level mapping of the information being handled.

The encoding process, often visible to end users, occurs each time an application needs to process any data. Web applications are not excluded from this. Like many other applications, they continuously process thousands of pieces of information even for simple requests.

Understanding the encoding schemes used by a web application can give you a big advantage during the detection and exploitation of a vulnerability.

#### 1.2.1. Charset
Internet users, via their web browsers, request billions of pages everyday. All of the content of these pages are displayed according to a charset.

But what is a [charset](http://www.iana.org/go/rfc2978)?
As the word suggests, it contains a set of characters: they represent the set of all symbols that the end user can display in their browser window. In technical terminology, a charset contains of pairs of symbols and code points.

The symbol is what the user reads, as she sees it on the screen.
The code point is a numeric index, used to distinguish unambiguously, the symbol within the charset. A symbol can be shown only if it exists in the charset.
Examples of charsets are: ASCII, Unicode, Latin-1, and so on.

###### ASCII
The ASCII (American Standard Code for Information Interchange) charset contains a small set of symbols. Originally it was 128 only, but now it is usually defined by its extended version, for a total of 255. It is old and it was designed to support only US symbols.

For example, ASCII cannot be used to display Chinese symbols, like many others. The ASCII charset does not contain symbols like σ and Σ. [Complete list][http://www.ascii-code.com/]

Examples:
|Code|Hex|Symbol|
|----|---|------|
| 65 |41 |  A   |
| 66 |42 |  B   |
| 67 |43 |  C   |
| 68 |44 |  D   |
| .. |.. |  ..  |

###### Unicode
Unicode (Universal Character Set) is the character encoding standard created to enable people around the world to use computers in any language. It supports all the world's writing systems. [Here](http://unicode-table.com/en/#0032) you can find the whole Unicode charset.

#### 1.2.2. CharSet vs CharSet Encoding
[Character encoding](http://www.w3.org/International/articles/definitions-characters/) (or simply encoding) is the representation, in bytes, of the symbols of a charset: a mapping of the symbols tot a series of ordered bytes so that your data can get to you.
A symbol can be represented by using one or more bytes.

###### 1.2.2.1. Unicode Encoding
Unicode has 3 main types of implementation of character encoding: UTF-8, UTF-16, and UTF-32, where UTF stands for Unicode Transformation Format.

The numbers 8, 16, and 32 are the amount of bits used to represent code points.
For example, the same symbol will be represented as follow:
|Symbol|Unicode|   UTF-8  |UTF-16|  UTF-32   |
|------|-------|----------|------|-----------|
|  !   |U+0021 |    21    |00 21 |00 00 00 21|
|  W   |U+0057 |    57    |00 57 |00 00 00 57|
|  ⮀  |U+2B80 | E2 AE 80 |2B 80 |00 00 2B 80|
|  ⌗  |U+2317 | E2 8C 97 |23 17 |00 00 23 17|

###### 1.2.2.2. HTML Encoding
Even in HTML it is important to consider the information integrity of the URLs and ensure that agents (browsers and others) display data correctly.

There are two main issues to address: inform the user agent on which character encoding is going to be used, and preserve the real meaning of some characters that have special significance.

According to the [HTTP 1.1 RFC](https://tools.ietf.org/html/rfc2616), documents transmitted via HTTP can send a charset parameter in the header to specify the character encoding of the document sent: this is the HTTP header `Content-Type`.<br>
  HTML4
  ```
  <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1">
  ```
  HTML5
  ```
  <meta charset="UTF-8">
  ```

If not defined, the RFC defines as default charset the *ISO-8859-1* : "8-bit single byte coded graphic characters sets" aka *Latin 1*.
Setting incorrect charset or simply omitting it can bring on some really unexpected behavior. If you intentionally set an incorrect charset, your browser may not display some symbols correctly.

These encoding schemas that we have talked about so far can be applied to all applications.

###### HTML Entities
An HTML entity is simply a string that corresponds with a symbol. It starts with `&` or `&#` and ends with `;`.

When the browser encounters an entity in an HTML page, it will show the symbol to the user and will never interpret the symbol as an HTML language element.

Example:<br>
  As the standard states, character references must start with a **U+0026 AMPERSAND** character `&` and following this there are multiple ways to represent character references:
  | Character References | Rule | Encoded Character |
  |----------------------|------|-------------------|
  | Named entity         | `&` + [named character references](http://www.w3.org/html/wg/drafts/html/master/syntax.html#named-character-references) + `;` | `&lt;` |
  | Numeric Decimal      | `&` + `#` + `D` + `;`  with `D`: decimal number | `&#60;` |
  | Numeric Hexadecimal  | `&` + `#x` + `H` + `;` with `H`: hex number | `&#x3c;` or `&#x3C;` |

Although the primary purpose of HTML entities is not to be a security feature, its use can limit most client side attacks (ie: XSS).

We will discuss this more in the following chapters.

###### 1.2.2.3. URL Encoding (Percent Encoding)
As stated in the [RFC 3986](http://tools.ietf.org/html/rfc3986#section-2.1), URLs sent over the Internet must contain characters in the range of the US-ASCII code character set. If unsafe characters are present in an URL, encoding them is required.

This encoding is important because it limits the characters to be used in a URL to a subset of specific characters:
1. Unreserved Chars : `[a-zA-Z]` `[0-9]` `[-._~]`
2. Reserved Chars   : `: / ? # [ ] @ ! $ & " ( ) * + , ; = %`

Other characters are encoded by the use of a percent char (`%`) plus two hexadecimal digits. Reserved chars must be encoded when they have no special role inside the URL. Here is a list of common encoded characters:
|Character|Purpose in URL         |Encoding|
|---------|-----------------------|--------|
|   #     |Separate anchors       |%23|
|   ?     |Separate query string  |%3F|
|   &     |Separate query elements|%24|
|   +     |Indicates a space      |%2B|

When you visit a site, URL-encoding is performed automatically by your browser.
This happens behind the scenes of your browser while you surf.
[Here](http://www.w3schools.com/tags/ref_urlencode.asp) is a complete URL-encoding reference.

Although it appears to be a security feature, URL-encoding is not.
It is only a method used to send data across the Internet but, it can lower (on enlarge) the attack surface (in some cases).

Generally, web browsers automatically perform URL-encoding, and if a server-side script engine is present, it will automatically perform URL-encoding.

###### 1.2.2.4. Base64
Base64 is a binary-to-text encoding schema used to convert binary files and send them over the Internet. For example, the e-mail protocol makes massive use of this encoding to attach files to message.

The HTML language permits the inclusion of some resources by using this encoding. For example, an image can be included in a page by inserting its binary content that has been converted to base64.

The alphabet of the Base64 encoding scheme is composed of digits `[0-9]` and Latin letters, both upper and lower case `[a-zA-Z]`, for a total of 62 values. To complete the character set to 64 there are the plus (`+`) and slash (`/`) characters.

Different implementations however, may use other values for the latest two characters and the one used for padding (`=`)

The following code shows an image in a web document. The server will send this image without the need to read it from another source like the file system. (see img-66)

In this chapter, we have discussed the major encoding schemas, but that is not all of them.
In fact, remember that any web designer or developer could easily create their own encoding schema.

___________________________________
## 1.3. Same Origin
One of the most important and critical points of web application security is the same origin policy.
The policy prevents a script or document from getting or setting properties of another document that come from a different origin.

Notes:
  CSS stylesheets, images, and scripts are loaded by the browser without consulting the policy.

**Same Origin Policy** (SOP) is consulted when cross-site HTTP requests are initiated from within client side scripts (ie: JavaScript), or when an Ajax request is run.

#### 1.3.1. Origin Definition
The origin is defined by the following triplet:
- Protocol : (ie: `http`)
- Host : (ie: `www.elsptp.site` Top Level Domain (TLD): `site`, SLD: `elsptp`, Third Level Domain: `www`)
- Port : (ie: `80`)

Let us see some SOP examples applied to the following address" http://els.wapt.com/index.php:
| URL                                |SOP| Reason                        |
|------------------------------------|---|-------------------------------|
|http://els.ptp.site/admin/index.php | v | Same protocol, host, and port |
|https://els.ptp.site/index.php      | x | Different protocol            |
|http://els.ptp.site/index.php:8080  | x | Different port                |
|http://www.els.ptp.site/index.php   | x | Different host                |
Content from `about:blank`, `Javascript:` and `data:` inherits the origin.

Important:
  It is important to know that Internet Explorer works a slightly different from other browsers. It has 2 exceptions:
  - Port : it does not consider the port as a component to the Same Origin Policy
  - Trust Zone : the Same Origin Policy is not applied to domains that are in highly trusted zone (i.e. corporate domains)

#### 1.3.2. What Does SOP Protect From?
In order to prevent someone (with different SOP) to run malicious page, for example, to capture your personal information.

#### 1.3.3. How SOP Works
The main rule of SOP is:
  "A document can access (through JavaScript) the properties of another document only if they have the same origin"

More precisely, the browser always performs the request successfully but it return the response to the user only if the SOP is respected.

With the term document, we are referring to an HTML page, an iframe included in the main page, or a response to an Ajax request. Images, styles information (`.css`) and Javascript file (`.js`) are excluded from the previous statement. They are always accessible regardless of their origin, and the browser loads them without consulting SOP.

###### 1.3.3.1. Example 1
`index.html` on domain `a.elsptp.site`
 (referred to as `origin1:http://a.elsptp.site`) wants to access, via an Ajax request (xhr), the `home.html` page on domain `b.elsptp.site` (referred to as `origin2:http://b.elsptp.site`)

The document `index.html` on domain `a.elsptp.site` cannot access, via an Ajax request (xhr) the `home.html` page on domain `b.elsptp.site`

###### 1.3.3.1. Example 2
We have two documents: the main document `http://www.elsptp.site/index.html` and the iframe document `http://www.elsptp.site/iframe.html`
  ```
  <html>
  ...
    <body>
      <iframe src="http://www.elsptp.site/iframe.html">
      </iframe>
    </body>
  </html>
  ```

The two document objects have the same origin, so each document can access the other via JavaScript. So, within the main document the following JavaScript instruction would be successful:
  ```
  window.frames[0].body= "Hello World";
  ```
Similarly, within the iframe document, the following JavaScript instruction would be successful:
  ```
  window.parent.body= "Hello World";
  ```

If we point the iframe to `http://www.mybank.bank` the previous JavaScript code would fail because the two windows do not have the same origin.

Keep the previous example in mind. SOP often defines the boundaries of many client-side attacks.

#### 1.3.4. Exceptions
There are several exceptions to SOP restrictions:
  - `window.location`
  - `document.domain`
  - Cross window messaging
  - Cross origin resource sharing (CORS)

###### 1.3.4.1. Window.location
A document can always write the `location` property of another document
The `window.location` object can be used to get the current page address (URL) and to redirect the browser to a new page.

Consider two documents in your browser with some existing relationship (ie: the first document includes the second via an iframe, or the second document has been opened by the first on with a `window.open` call).

Each document can write the location property of the other, but cannot read it, except with the case where 2 documents have the same origin.

This means that the location property can always be changed. But it is the same origin policy that determines whether a new document can be loaded.

  **Example:**
    Look at the following code http://www.coliseumlab.com/index.html :
    ```
    <html>
    ...
      <body>
        <iframe src="http://www.elearnsecurity.com/index.html">
        </iframe>
      </body>
    </html>
    ```
    Within the `index.html` document, the following JavaScript instruction is run successfully:
      ```
      window.frames[0].location=http://www.google.com;
      ```

  **Security Issues**
  A document can always update the `location` property of another document, if they have some relationship.

  Typical relationships are:
  - a document is embedded within another via an iframe element
  - one document is opened by the other via the `window.open` DOM API

  Here are some typical examples:
    A document **X**, included by another document **Y** via an iframe, can always change the location of **Y**.
      Code on **Y**:
        ```
        <html>
          <body>
            <iframe src='X'></iframe>
          </body>
        </html>
        ```
      Code on **X**:
        ```
        <html>
          <head>
            <script type="text/javascript">
              window.parent.location="http://www.google.com"
            </script>
          </head>
        </html>
        ```

    A document **X** opened by document **Y** through the `window.open` DOM API can always change the location of **Y**.
      Code on **Y**:
        ```
        <html>
          <head>
              <button name='Click' onclick="window.open(X);">
                Click
              </button>
          </head>
        </html>
        ```

      Code on **X**:
        ```
        <html>
          <head>
            <script type="text/javascript">
              window.opener.location="http://www.google.com";
            </script>
          </head>
        </html>
        ```


###### 1.3.4.2. Document.domain
Another important exception is related to the DOM property called `document.domain`
This property describes the domain portion of the origin of the current document.

A document with the URL http://subdomain.domain.com/index.html
has the `document.domain` property set to `subdomain.domain.com`

This property can be changed. A document can update its own `document.domain` to a higher level in the domain hierarchy, except for the top level (e.g. `.com`).

The second-level domain (e.g. `domain.com`) can be specified but it cannot be changed (e.g. from `domain.com` to `whitehouse.gov`).

By changing the `document.domain` property, a document slightly changes its own origin.

  **Example:**
  Let's say a document has the URL: http://a.elsptp.site/index.html
  It includes, via an iframe, another document belonging to a different origin http://b.elsptp.site/home.html

  Due to the SOP, the JavaScript code running from the context of the main document cannot access, via Javascript, the iframe content because the two documents came from different origin.

  The SOP can be circumvented, if the following JavaScript code (`document.domain="elsptp.site"`) is run by each of the two documents.
  In this manner, the two documents can be considered to have the same origin.
  (see img-104)
    `<iframe src="http://b.elsptp.site/home.html" />`
    **a.elsptp.site/index.html** -> http://b.elsptp.site
    ```
    <script>
        document.domain="elsptp.site"
    </script>
    ```

    **b.elsptp.site/home.html**
    ```
    <script>
      document.domain="elsptp.site"
    </script>
    ```

###### 1.3.4.3. Cross Window Messaging
The new HTML5 feature known as Cross Window Messaging permits different documents (iframes, popups, and current window) to communicate with each other regardless of the same origin policy by using a simple synchronous mechanism.

###### 1.3.4.4. Cross Origin Resource Sharing (CORS)
**Cross Origin Resource Sharing** is a set of specs built to allow a browser to access a few resources by bypassing the same origin policy.
The CORS architecture uses custom HTTP response headers and relies upon server-side components or server-side scripting languages.

This also will be dealt with in-depth in the HMTL5 module.

(see vid-107)

___________________________________
## 1.4. Cookies


___________________________________
## 1.5. Session


___________________________________
## 1.6. Web Application Proxies
