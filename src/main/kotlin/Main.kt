import KotlinAesEncoder.buildKey
import KotlinAesEncoder.decrypt
import KotlinAesEncoder.decryptWithPrefixIV
import KotlinAesEncoder.encrypt
import KotlinAesEncoder.encryptWithPrefixIV
import KotlinAesEncoder.generateIV
import KotlinAesEncoder.generateKey
import org.bouncycastle.crypto.CipherParameters

fun main() {
    println("----Random generated key + IV-----")
    runTest(
        key = generateKey(),
        iv = generateIV(),
        clearText = "Hello World AES, Welcome to Cryptography!"
    )

    println("----Random generated key + IV, embedded IV-----")
    runTestWithPrefixIv(
        key = generateKey(),
        iv = generateIV(),
        clearText = "Hello World AES, Welcome to Cryptography!"
    )

    println("----Salesforce provided example (https://ampscript.guide/encryptsymmetric)-----")
    runTest(
        key = buildKey(
            password = "fresh",
            salt = "e0cf1267f564b362".fromHex()
        ),
        iv = "4963b7334a46352623252955df21d7f3".fromHex(),
        clearText = "limedash",
        expectedEncryptedText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()
    )
}

fun runTest(key: CipherParameters, iv: ByteArray, clearText: String, expectedEncryptedText: ByteArray? = null) {
    val encryptedText = encrypt(key, clearText, iv)
    val decryptedText = decrypt(key, encryptedText, iv)

    assert(clearText, iv, encryptedText, decryptedText, expectedEncryptedText)
}

fun runTestWithPrefixIv(key: CipherParameters, iv: ByteArray, clearText: String) {
    val encryptedText = encryptWithPrefixIV(key, clearText, iv)
    val decryptedText = decryptWithPrefixIV(key, encryptedText)

    assert(clearText, iv, encryptedText, decryptedText)
}

fun assert(
    clearText: String,
    iv: ByteArray,
    encryptedText: ByteArray,
    decryptedText: String,
    expectedEncryptedText: ByteArray? = null
) {
    print("Input     (plain text)", clearText)
    print("IV        (hex)", iv.toHex())
    print("Encrypted (hex)", encryptedText.toHex())
    print("IV        (base64)", iv.toBase64())
    print("Encrypted (base64)", encryptedText.toBase64())
    expectedEncryptedText?.let { print("Expected  (base64)", it.toBase64()) }
    print("Decrypted (plain text)", decryptedText)

    check(expectedEncryptedText?.contentEquals(encryptedText) != false)
    check(decryptedText == clearText)

    println()
}

fun print(vararg args: Any?) {
    println(String.format("%-30s: %s", *args))
}
