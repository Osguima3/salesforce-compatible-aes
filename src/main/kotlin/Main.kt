import org.bouncycastle.util.encoders.Base64

const val AES_KEY_BIT_SIZE = 256
const val ITERATIONS = 1000
const val SALT = "e0cf1267f564b362"

fun main() {
    JavaAesEncoder.shouldPass()
    BouncyCastleAesEncoder.shouldPass()
    `AES-CBC-PKCS7Padding (Salesforce) should pass`()
}

fun `AES-CBC-PKCS7Padding (Salesforce) should pass`() = with(BouncyCastleAesEncoder) {
    val plainText = "limedash"
    val password = "fresh"
    val iv = "4963b7334a46352623252955df21d7f3".fromHex()
    val cipherText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()

    // The trick is block size 16, key size 32, pbkdf2 with 1000 iterations and padding pkcs7
    val secretKey = buildKey(password, SALT.toByteArray(), AES_KEY_BIT_SIZE, ITERATIONS)

    val encryptedText = encryptWithPrefixIV(secretKey, plainText, iv)
    val cipherTextWithIv = concat(iv, cipherText)
    val decryptedText = decryptWithPrefixIV(secretKey, encryptedText)
    print(plainText, iv, encryptedText, decryptedText, cipherTextWithIv)

    check(encryptedText.contentEquals(cipherTextWithIv))
    check(decryptedText == plainText)
    println()
}

private fun <Key> AesEncoder<Key>.shouldPass(
    secretKey: Key = generateKey(AES_KEY_BIT_SIZE),
    iv: ByteArray = generateIV(),
    plainText: String = "Hello World AES, Welcome to Cryptography!"
) {
    val encryptedText = encryptWithPrefixIV(secretKey, plainText, iv)
    val decryptedText = decryptWithPrefixIV(secretKey, encryptedText)
    print(iv, plainText, encryptedText, decryptedText)
    check(decryptedText == plainText)
    println()
}

private fun print(
    iv: ByteArray,
    plainText: String,
    encryptedText: ByteArray,
    decryptedText: String,
    expectedEncryptedText: ByteArray? = null
) {
    print("Input     (plain text)", plainText)
    print("IV        (hex)", iv.toHex())
    print("Encrypted (hex)", encryptedText.toHex())
    print("IV        (base64)", iv.toBase64())
    print("Encrypted (base64)", encryptedText.toBase64())
    print("Expected  (base64)", expectedEncryptedText?.toBase64() ?: "-")
    print("Decrypted (plain text)", decryptedText)
}

fun print(vararg args: Any?) {
    println(String.format("%-30s: %s", *args))
}

fun ByteArray.toHex(): String = buildString {
    this@toHex.forEach { append(String.format("%02x", it)) }
}

fun String.fromHex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun ByteArray.toBase64(): String = Base64.toBase64String(this)

fun String.fromBase64(): ByteArray = Base64.decode(this)
