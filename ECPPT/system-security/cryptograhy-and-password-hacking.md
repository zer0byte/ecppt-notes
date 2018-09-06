# [ECPPT](https://members.elearnsecurity.com/courses/penetration_testing_professional_v5)
__________________________
# System Security
# Module 5 - Cryptography

https://cdn.members.elearnsecurity.com/ptp_v5/section_1/module_5/html/index.html

_____________________________________________________
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


_______________________________________
## 8. Windows 2000/XP/2k3/Vista/7/8 Passwords
