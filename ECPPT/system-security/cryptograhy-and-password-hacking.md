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


________________________________________
## 5. Secure Shell (SSH)


________________________________________
## 6. Cryptographic Attack


________________________________________
## 7. Security Pitfalls


________________________________________
## 8. Windows 2000/XP/2k3/Vista/7/8 Passwords
