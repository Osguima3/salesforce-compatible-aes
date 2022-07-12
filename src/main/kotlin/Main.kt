import java.nio.ByteBuffer
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.min

fun main() {
    `AES-CBC-PKCS5Padding should pass`()
    `AES-CBC-PKCS5Padding (Salesforce) should pass`()
}

fun `AES-CBC-PKCS5Padding should pass`() {
    val ENCRYPT_ALGO = "AES/CBC/PKCS5Padding"
    val BLOCK_SIZE = 16
    val IV_LENGTH_BYTE = 16
    val AES_KEY_BIT = 256

    val plainText = "Hello World AES, Welcome to Cryptography!"
    val secretKey = getAESKey(AES_KEY_BIT)
    val iv = getRandomNonce(IV_LENGTH_BYTE)

    val parameterSpec = { it: ByteArray -> IvParameterSpec(it) }
    val encryptedText = encryptWithPrefixIV(plainText.toByteArray(), secretKey, iv, ENCRYPT_ALGO, parameterSpec(iv))

    println("\n------ AES Encryption ------")
    print("Input (plain text)", plainText)
    print("Key (hex)", hex(secretKey.encoded))
    print("IV  (hex)", hex(iv))
    print("Encrypted (hex) ", hex(encryptedText))
    print("Encrypted (hex) (block = 16)", hex(encryptedText, BLOCK_SIZE))

    println("\n------ AES Decryption ------")
    print("Input (hex)", hex(encryptedText))
    print("Input (hex) (block = 16)", hex(encryptedText, BLOCK_SIZE))
    print("Key (hex)", hex(secretKey.encoded))

    val decryptedText = decryptWithPrefixIV(encryptedText, secretKey, iv.size, ENCRYPT_ALGO, parameterSpec)
    print("Decrypted (plain text)", decryptedText)
}

fun `AES-CBC-PKCS5Padding (Salesforce) should pass`() {
    // The trick is block size 16, key size 32, pbkdf2 with 1000 iterations and padding pkcs7
    val ENCRYPT_ALGO = "AES/CBC/PKCS5Padding"
    val BLOCK_SIZE = 16
    val AES_KEY_BIT = 256
    val ITERATIONS = 1000

    val plainText = "limedash"
    val password = "fresh"
    val salt = "e0cf1267f564b362"
    val iv = "4963b7334a46352623252955df21d7f3".toByteArray()

    val cipher = "4fKWdv7fJRkFsYO6RRtrMg=="

//        val iv = "9b1af98d181bbb6d".toByteArray()
//        val iv = "9b1af98d181bbb6d041a7cfff2f89335".toByteArray()

    val secretKey = getAESKey(password.toCharArray(), salt.toByteArray(), AES_KEY_BIT, ITERATIONS)
    val parameterSpec = { it: ByteArray -> IvParameterSpec(it) }
    val encryptedText = encryptWithPrefixIV(plainText.toByteArray(), secretKey, iv, ENCRYPT_ALGO, parameterSpec(iv))

    println("\n------ AES Encryption ------")
    print("Input (plain text)", plainText)
    print("Key (hex)", hex(secretKey.encoded))
    print("IV  (hex)", hex(iv))
    print("Encrypted (hex) ", hex(encryptedText))
    print("Encrypted (base64) ", encryptedText.toBase64())
    print("Encrypted (hex) (block = 16)", hex(encryptedText, BLOCK_SIZE))

    println("\n------ AES Decryption ------")
    print("Input (hex)", hex(cipher.fromBase64()))
    print("Input (hex) (block = 16)", hex(cipher.fromBase64(), BLOCK_SIZE))
    print("Key (hex)", hex(secretKey.encoded))

    val decryptedText = decryptWithPrefixIV(cipher.fromBase64(), secretKey, iv.size, ENCRYPT_ALGO, parameterSpec)
    print("Decrypted (plain text)", decryptedText)
    print("Decrypted (plain text)", decryptedText)
}

private fun print(vararg args: Any) {
    println(String.format("%-30s:%s", *args))
}


fun getRandomNonce(byteSize: Int): ByteArray =
    ByteArray(byteSize).apply(SecureRandom()::nextBytes)

// AES secret key
fun getAESKey(keySize: Int): SecretKey =
    KeyGenerator.getInstance("AES")
        .apply { init(keySize, SecureRandom.getInstanceStrong()) }
        .generateKey()

// Password derived AES secret key
fun getAESKey(password: CharArray, salt: ByteArray, keySize: Int = 256, iterationCount: Int = 65536): SecretKey =
    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(PBEKeySpec(password, salt, iterationCount, keySize))
        .let { SecretKeySpec(it.encoded, "AES") }

// hex representation
fun hex(bytes: ByteArray): String = buildString {
    bytes.forEach { append(String.format("%02x", it)) }
}

// print hex with block size split
fun hex(bytes: ByteArray, blockSize: Int): String {
    var blockSize = blockSize
    val hex = hex(bytes)

    // one hex = 2 chars
    blockSize *= 2

    // better idea how to print this
    val result = mutableListOf<String>()
    var index = 0
    while (index < hex.length) {
        result += hex.substring(index, min(index + blockSize, hex.length))
        index += blockSize
    }
    return result.toString()
}

// prefix IV length + IV bytes to cipher text
fun encryptWithPrefixIV(
    plainText: ByteArray,
    secret: SecretKey,
    iv: ByteArray,
    algorithm: String,
    paramSpec: AlgorithmParameterSpec
): ByteArray = with(encrypt(plainText, secret, algorithm, paramSpec)) {
    ByteBuffer.allocate(iv.size + size)
        .put(iv).put(this)
        .array()
}

// AES-GCM needs GCMParameterSpec
fun encrypt(plainText: ByteArray, secret: SecretKey, algorithm: String, paramSpec: AlgorithmParameterSpec): ByteArray =
    Cipher.getInstance(algorithm)
        .apply { init(Cipher.ENCRYPT_MODE, secret, paramSpec) }
        .doFinal(plainText)

fun decryptWithPrefixIV(
    cText: ByteArray,
    secret: SecretKey,
    ivLength: Int,
    algorithm: String,
    parameterSpec: (ByteArray) -> AlgorithmParameterSpec
): String = with(ByteBuffer.wrap(cText)) {
    val iv = ByteArray(ivLength).also(::get)
    val cipherText = ByteArray(remaining()).also(::get)
    decrypt(cipherText, secret, algorithm, parameterSpec(iv))
}

fun decrypt(cText: ByteArray, secret: SecretKey, algorithm: String, paramSpec: AlgorithmParameterSpec): String =
    Cipher.getInstance(algorithm)
        .apply { init(Cipher.DECRYPT_MODE, secret, paramSpec) }
        .doFinal(cText)
        .let(::String)

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this)
