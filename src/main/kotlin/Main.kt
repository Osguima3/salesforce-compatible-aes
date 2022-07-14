import BouncyCastleAesEncoder.buildKey
import BouncyCastleAesEncoder.decrypt
import BouncyCastleAesEncoder.decryptWithPrefixIV
import BouncyCastleAesEncoder.encrypt
import BouncyCastleAesEncoder.encryptWithPrefixIV
import BouncyCastleAesEncoder.generateIV
import BouncyCastleAesEncoder.generateKey
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.util.encoders.Base64

fun main() {
    println("----Random generated key + IV-----")
    runTest(
        key = generateKey(AES_KEY_BIT_SIZE),
        iv = generateIV(),
        plainText = "Hello World AES, Welcome to Cryptography!"
    )

    println("----Random generated key + IV, embedded IV-----")
    runTestWithPrefixIv(
        key = generateKey(AES_KEY_BIT_SIZE),
        iv = generateIV(),
        plainText = "Hello World AES, Welcome to Cryptography!"
    )

    println("----Salesforce provided example (https://ampscript.guide/encryptsymmetric)-----")
    runTest(
        key = buildKey(
            password = "fresh",
            salt = "e0cf1267f564b362".fromHex()
        ),
        iv = "4963b7334a46352623252955df21d7f3".fromHex(),
        plainText = "limedash",
        expectedEncryptedText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()
    )
}

fun runTest(key: CipherParameters, iv: ByteArray, plainText: String, expectedEncryptedText: ByteArray? = null) {
    val encryptedText = encrypt(key, plainText, iv)
    val decryptedText = decrypt(key, encryptedText, iv)

    assert(plainText, iv, encryptedText, decryptedText, expectedEncryptedText)
}

fun runTestWithPrefixIv(key: CipherParameters, iv: ByteArray, plainText: String) {
    val encryptedText = encryptWithPrefixIV(key, plainText, iv)
    val decryptedText = decryptWithPrefixIV(key, encryptedText)

    assert(plainText, iv, encryptedText, decryptedText)
}

fun assert(
    plainText: String,
    iv: ByteArray,
    encryptedText: ByteArray,
    decryptedText: String,
    expectedEncryptedText: ByteArray? = null
) {
    print("Input     (plain text)", plainText)
    print("IV        (hex)", iv.toHex())
    print("Encrypted (hex)", encryptedText.toHex())
    print("IV        (base64)", iv.toBase64())
    print("Encrypted (base64)", encryptedText.toBase64())

    expectedEncryptedText?.let {
        print("Expected  (base64)", it.toBase64())
        check(it.contentEquals(encryptedText))
    }

    print("Decrypted (plain text)", decryptedText)
    check(decryptedText == plainText)

    println()
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
