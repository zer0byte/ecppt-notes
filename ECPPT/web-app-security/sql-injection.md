# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
___________________________________
# Web App Security
# Module 4 - SQL Injection

https://cdn.members.elearnsecurity.com/ptp_v5/section_5/module_4/html/index.html

###### Module Map
1. Introduction to SQL Injection
2. Finding SQL Injection
3. Exploiting In-Band SQL Injection
4. Exploiting Error-Based SQL Injection
5. Exploiting Blind SQL Injection
6. SQLMap
7. Mitigation Strategies
8. From SQLi to Server Takeover

____________________________________________________
## 4.1. Introduction to SQL Injection
An **SQL Injection (SQLi)** attack exploits the injection of SQL commands into SQL queries of a web application. A successful SQLi attack lets a malicious hacker access and manipulate a web application's backend database.

Complex web applications generally use database for storing data, user credentials, or statistics; CMSs as well as simple personal web pages can connect to databases such as *MySQL*, *SQL Server*, *Oracle*, *PostgreSQL*, and others.

To interact with databases, entities such as systems operators, programmers, applications, and web applications use **Structured Query Language (SQL)**

SQL is a powerful interpreted language used to extract and manipulate data from a database. Web applications embed SQL commands, also known as queries, in their server side code.

The code takes care of establishing and keeping the connection to the database by using **connectors**. Connectors are middle-ware between the web application and the database.
  Connector example:
    ```
                      Application
                  ^        ^        ^
                  |        |        |
                  V        |        |
          Driver Manager   |        |
                  ^        |        |
                  |        V        |
                  |      DNS        |
                  |  Configuration  |
                  |        ^        |
                  |        |        |
                  V        V        V
                    Connector/ODBC
                           ^
                           |
                           V
                     MySQL Server
    ```

Before learning how to carry out an attack, we have to know some SQL basics:
- SQL statement syntax
- How to perform a query
- How to *union* the results of 2 queries
- The *DISTINCT* and *ALL* operators
- How comments work

#### 4.1.1. SQL Statements
You can find more information about SQL [here](http://www.w3schools.com/sql/sql_intro.asp)

It is also possible to select constant values:
  ```
  SELECT 22, 'string', 0x12, 'another string';
  ```

You also need to know the **UNION** command, which performs a union between 2 results, operates:
  ```
  <SELECT statement> UNION <other SELECT statement>;
  ```

If a table or query contains duplicate rows, you can use the
  ```
  SELECT **DISTINCT** <field list> <remainder of statement>;
  ```

A *UNION* statement implies *DISTINCT* by default. You can prevent that by using the **ALL** operator:
  ```
  <SELECT statement> UNION ALL <other SELECT statement>;
  ```

Finally a word about **comments**. There are 2 strings you can use to comment a line in SQL:
  - `#` (the hash symbol)
    ```
    SELECT field FROM table; # this is a comment
    ```
  - `-- ` (two dashes followed by a space)
    ```
    SELECT field FROM table; -- this is a comment
    ```

**Example:**
  In the following slides, we will see some SQL queries performed on a database containing 2 tables:
  **Products**
    |ID  |Name    |Description     |
    |----|--------|----------------|
    |1   |Shoes   |Nice shoes      |
    |3   |Hat     |Black hat       |
    |18  |T-Shirt |Cheap           |

  **Accounts**
    |Username |Password |Email             |
    |---------|---------|------------------|
    |admin    |HxZsO9AR |admin@site.com    |
    |staff    |ihKdNTU4 |staff@site.com    |
    |user     |lwsi7Ks8 |usr@othersite.com |


  The following 2 queries provide the same result:
    ```
    SELECT Name, Description FROM Products WHERE ID='1';
    SELECT Name, Description FROM Products WHERE Name='Shoes';
    ```

  This is a **UNION** example between 2 SELECT statements:
    ```
    SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts;
    ```

  You can also perform a UNION operation with some chosen data:
    ```
    SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT 'Example', 'Data';
    ```

#### 4.1.2. SQL Queries Inside Web Applications
The previous examples show how to use SQL when querying a database directly from its console.

To perform the same tasks from within a web application, the application must:
- **Connect** to the database
- **Submit** the query to the database
- **Retrieve** the results

Then the application logic can use the results.

The following code contains a PHP example of a connection to a MySQL database and the execution of a query.
  Example:
    ```
    $dbhostname = '1.2.3.4';
    $dbuser = 'username';
    $dbpassword = 'password';
    $dbname = 'database';

    $connection = mysqli_connect($dbhostname, $dbpassword, $dbname);
    $query = "SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts;";

    $results = mysqli_query($connection, $query);
    display_results($results);
    ```

The previous example shows a **static query** example inside a PHP page:
- `$connection` is an object referencing the connection to the database
- `$query` contains query
- `mysqli_query` is a function which submits the query to the database
- Finally the custom `display_results()` function renders the data

Anatomy of a database interaction in PHP. This example uses a MySQL database:
  ```
  // Configuration
  $dbhostname = '1.2.3.4';
  $dbuser = 'username';
  $dbpassword = 'password';
  $dbname = 'database';

  $connection = mysqli_connect($dbhostname, $dbpassword, $dbname); // Connection
  $query = "SELECT Name, Description FROM Products WHERE ID='3' UNION SELECT Username, Password FROM Accounts;"; // Query definition

  $results = mysqli_query($connection, $query); // Submit
  display_results($results); // Usage
  ```

#### 4.1.3. Vulnerable Dynamic Query

However, most of the times queries are not static, they are **dynamically built** by using the user's inputs. Here you can find a **vulnerable** dynamic query example:
  ```
  $id = $_GET['id'];

  $connection = mysqli_connect($dbhostname, $dbpassword, $dbname);
  $query = "SELECT Name, Description FROM Products WHERE ID='$id';";

  $results = mysqli_query($connection, $query);
  display_results($results);
  ```

  The previous example shows some code which uses **user supplied input to build a query** (the *id* parameter of the GET request). The code then submits the query to the database.

  Although the code is functionally correct, this behavior is very dangerous, because a malicious user can exploit the query construction to take control of the database interaction.

  Let us see how!

The dynamic query:
  ```
  SELECT Name, Description FROM Products WHERE ID='$id';
  ```
  Expects *$id* values such as:
  - `1` => `SELECT Name, Description FROM Products WHERE ID='1';`
  - `Example` => `SELECT Name, Description FROM Products WHERE ID='Example';`
  - `Itid3` =>`SELECT Name, Description FROM Products WHERE ID='Itid3';`
  Or any other string.

But what if the attacker crafts a `$id` value which can actually **change** the query?
  Something like:
    ```
    ' OR 'a'='a
    ```
  Then the query becomes:
    ```
    SELECT Name, Description FROM Products WHERE ID='' OR 'a'='a';
    ```

  This tells the database to select the items by checking two conditions:
  - The id must be empty (`id=''`)
  - **OR** an always true condition (`'a'='a'`)

  While the first condition is not met, the SQL engine will consider the second condition of the OR. This second condition is crafted as an always true condition.

  In other words, this tells the database to select all the items in the *Product* table!

An attacker could also exploit the UNION command by supplying:
  ```
  UNION SELECT Username, Password FROM Accounts WHERE 'a'='a
  ```
  Thus changing the query to:
  ```
  SELECT Name, Description FROM Products WHERE ID='' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a';
  ```

  This asks the database tot select the items with an **empty** id, thus selecting an empty set, and then to perform a union with all the entries in the *Accounts* table.

  By using some deep knowledge about the database management system in use, an attacker can get access to the entire database just by using a web application.

#### 4.1.4. How Dangerous is a SQL Injection
Before going deeper into the **find and exploit process** of SQL injection vulnerabilities, you should understand where these vulnerabilities can lead when they are successfully exploited.

First, we have to understand that based on the DBMS that the web application is using (MySQL, SQL Server,...), the attacker is capable of performing a number of actions that go much further than the mere manipulation of the database.

  An attacker could read the file systems, run OS commands, install shells, access the remote network, and basically own the whole infrastructure.

  This is not always the case however, as we will see later, the more powerful the DBMS, the more advanced the SQL is.
  This increases the capabilities of an attacker after the exploitation.

  Keep in mind that accessing a database that stores confidential data (user credentials, SSNs, credit cards, and whatever sensitive information an enterprise, company, or individual may store in a database) is the single most dangerous form of attack on a web application.

Among all the vulnerabilities that may affect web applications, SQL injections are the **first checked by hackers** because of the fact that they produce the most immediate results.
  Example:
    An XSS attacks involves some steps, intelligence, and planning for its successful exploitation. An SQL injection vulnerability, once found, is ready to be exploited.

#### 4.1.5. SQLi Attack Classification
There is a great deal of literature about SQLi and there are many different types of classifications, each one based on different aspects such as:
- Scope of the attack
- Exploitation vector
- Source of the attack

In this section we will refer 3 different **injection attacks and exploitation** types:
- **In-band**
- **Error-based**
- **Blind SQL**

These classifications are based on the exploitation method used to carry out the attack. This will help you follow the explanations of the detection and exploitation phases. Now let's see it in detail!

**In-band SQL Injection** leverage the same channel used to inject the SQL code (i.e. the pages generated by the web application).
  Example:
    During an in-band attack the penetration tester finds a way to ask the web application for the desired information.

During an **Error-Based SQL Injection Attack**, the penetration testers tries to force the DBMS to output an error message and then uses that information to perform data exfiltration.
  Example:
    To exploit an error-based injection, the penetration tester needs to use advanced DBMS features. Errors could be sent either via the **web application output or by other means** such as automated reports or warning emails.

A web application vulnerable to **blind SQL injection** does not reflect the results of the injection on the output. In this case the penetration tester must find an **inference** method to exploit the vulnerability.
  Example:
    Inference exploitation is usually carried out by using true/false conditions.
    The penetration tester can understand if a condition is true or false by studying the web application behavior.

____________________________________________________
## 4.2. Finding SQL Injection
To exploit an SQL Injection you have to first find out where the **injection point** is, then you can craft a **payload** to take control over your target's dynamic query.

The most straightforward way to find SQL injections within a web application is to probe its inputs with characters that are known to cause the SQL query to be syntactically invalid and thus forcing the web application to return an error

Note: Not all the inputs of a web applications are used to build SQL queries. In the *Information Gathering* module, we suggested that you categorize the different input parameters and save the ones used for database data retrieval and manipulation.

In the following slides, we will see how to use the information gathered to identify and exploit SQLi vulnerabilities.

Input parameters are carried through: **GET and POST requests, HEADERS and COOKIES**.
We have to check all these channels where data is retrieved from the client.

The following examples, for the sake of simplicity, will examine scenarios where inputs are taken straight from the URL (with the GET method). The same techniques apply to other channels.

For the purpose of explaining the process of finding SQL Injections, we created a small (vulnerable) e-commerce web application showing cell phones for sale.
  Example:
    `ecommerce.php` takes an input parameter named `id` that read the product features from the database and prints them out on the page.

    The `id` parameter is expected to be an integer.
    Sending the `id=1` GET parameter makes the application behave correctly. (see img-50)






____________________________________________________
## 4.3. Exploiting In-Band SQL Injection



____________________________________________________
## 4.4. Exploiting Error-Based SQL Injection



____________________________________________________
## 4.5. Exploiting Blind SQL Injection



____________________________________________________
## 4.6. SQLMap



____________________________________________________
## 4.7. Mitigation Strategies



____________________________________________________
## 4.8. From SQLi to Server Takeover
