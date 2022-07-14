# Salesforce compatible AES

Java and Kotlin implementations of AES, compatible with Salesforce's AMPScript method [EncodeSymmetric](https://ampscript.guide/encryptsymmetric).

This algorithm can be used to safely communicate both ways between Salesforce and a JVM-based service of your own.

The provided solutions will work against this encryption snippet in AMPScript:

```java
set @str = "limewire"

set @password = "fresh"
set @salt = "e0cf1267f564b362"
set @initVector = "4963b7334a46352623252955df21d7f3"

set @encryptedAES = EncryptSymmetric(@str, "aes", @null, @password, @null, @salt, @null, @initVector) 
```

**NOTE: Salesforce does not embed the IV in the cipher text, so you will need to pass it along**

AMPScript's default AES implementation is based on a 256 bit key size, CBC with 16 byte block size, and PKCS7 with 1000 iterations.

The only required dependency is the BouncyCastle library, given the fact that the core Java libraries lack a PKCS7 implementation.
