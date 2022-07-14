import org.bouncycastle.util.encoders.Base64

const val AES_KEY_BIT_SIZE = 256
const val ITERATIONS = 1000

fun main() {
    println("----Java-----")
    JavaAesEncoder.`should pass`()

    println("----Bouncy Castle-----")
    BouncyCastleAesEncoder.`should pass`()

    println("----Salesforce (Example at https://ampscript.guide/encryptsymmetric)-----")
    `AES-CBC-PKCS7Padding (Salesforce) should pass`()
}

fun `AES-CBC-PKCS7Padding (Salesforce) should pass`() = with(BouncyCastleAesEncoder) {
    `should pass`(
        secretKey = buildKey(
            password = "fresh",
            salt = "e0cf1267f564b362".fromHex(),
            keySize = AES_KEY_BIT_SIZE,
            iterationCount = ITERATIONS
        ),
        iv = "4963b7334a46352623252955df21d7f3".fromHex(),
        plainText = "limedash",
        expectedEncryptedText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()
    )
}

private fun <Key> AesEncoder<Key>.`should pass`(
    secretKey: Key = generateKey(AES_KEY_BIT_SIZE),
    iv: ByteArray = generateIV(),
    plainText: String = "Hello World AES, Welcome to Cryptography!",
    expectedEncryptedText: ByteArray? = null
) {
    val encryptedText = encrypt(secretKey, plainText, iv)
    val decryptedText = decrypt(secretKey, encryptedText, iv)
    print(iv, plainText, encryptedText, decryptedText, expectedEncryptedText)
    check(decryptedText == plainText)
    expectedEncryptedText?.let { check(it.contentEquals(encryptedText)) }
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
