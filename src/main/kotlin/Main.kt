import AesEncoder.decryptWithPrefixIV
import AesEncoder.encryptWithPrefixIV
import AesEncoder.getAESKey
import AesEncoder.getRandomIV
import java.util.Base64
import javax.crypto.SecretKey

const val AES_KEY_BIT_SIZE = 256

fun main() {
    `AES-CBC-PKCS5Padding should pass`()
    `AES-CBC-PKCS5Padding (Salesforce) should pass`()
}

fun `AES-CBC-PKCS5Padding should pass`() {
    val plainText = "Hello World AES, Welcome to Cryptography!"
    val secretKey = getAESKey(AES_KEY_BIT_SIZE)
    val iv = getRandomIV()

    val encryptedText = encrypt(secretKey, plainText, iv)

    val decryptedText = decrypt(secretKey, encryptedText)
    check(decryptedText == plainText)
}

fun `AES-CBC-PKCS5Padding (Salesforce) should pass`() {
    // The trick is block size 16, key size 32, pbkdf2 with 1000 iterations and padding pkcs7
    val ITERATIONS = 1000

    val plainText = "limedash"
    val password = "fresh"
    val salt = "e0cf1267f564b362"
    val iv = "4963b7334a46352623252955df21d7f3".fromHex()
    val cipherText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()
    val secretKey = getAESKey(password.toCharArray(), salt.toByteArray(), AES_KEY_BIT_SIZE, ITERATIONS)

    val encryptedText = encrypt(secretKey, plainText, iv)
    check(encryptedText.contentEquals(cipherText))

    val decryptedText = decrypt(secretKey, encryptedText)
    check(decryptedText == plainText)
}

private fun encrypt(secretKey: SecretKey, plainText: String, iv: ByteArray): ByteArray {
    val encryptedText = encryptWithPrefixIV(plainText.toByteArray(), secretKey, iv)
    println("\n------ AES Encryption ------")
    print("Input     (plain text)", plainText)
    print("Key       (hex)", secretKey.encoded.toHex())
    print("IV        (hex)", iv.toHex())
    print("Encrypted (hex)", encryptedText.toHex())
    print("Key       (base64)", secretKey.encoded.toBase64())
    print("IV        (base64)", iv.toBase64())
    print("Encrypted (base64) ", encryptedText.toBase64())
    return encryptedText
}

private fun decrypt(secretKey: SecretKey, encryptedText: ByteArray): String {
    val decryptedText = decryptWithPrefixIV(encryptedText, secretKey)
    println("\n------ AES Decryption ------")
    print("Input     (hex)", encryptedText.toHex())
    print("Key       (hex)", secretKey.encoded.toHex())
    print("Input     (base64)", encryptedText.toBase64())
    print("Key       (base64)", secretKey.encoded.toBase64())
    print("Decrypted (plain text)", decryptedText)
    return decryptedText
}

fun print(vararg args: Any) {
    println(String.format("%-30s: %s", *args))
}

fun ByteArray.toHex(): String = buildString {
    this@toHex.forEach { append(String.format("%02x", it)) }
}

fun String.fromHex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this)
