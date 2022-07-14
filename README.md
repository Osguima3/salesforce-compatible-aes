# Salesforce compatible AES

Java and Kotlin implementations of AES, compatible with Salesforce's AMPScript method [EncodeSymmetric](https://ampscript.guide/encryptsymmetric).

AMPScript's AES implementation is based on a 256 bit key size, CBC with 16 byte block size, and PKCS7 with 1000 iterations.

The provided solutions will work against this encryption snippet in AMPScript:

```java
set @str = "limewire"

set @password = "fresh"
set @salt = "e0cf1267f564b362"
set @initVector = "4963b7334a46352623252955df21d7f3"

set @encryptedAES = EncryptSymmetric(@str, "aes", @null, @password, @null, @salt, @null, @initVector) 
```
