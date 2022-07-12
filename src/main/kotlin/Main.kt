import AesEncoder.decryptWithPrefixIV
import AesEncoder.encrypt
import AesEncoder.getAESKey
import AesEncoder.getRandomIV
import java.util.Base64
import javax.crypto.SecretKey

const val AES_KEY_BIT_SIZE = 256
const val ITERATIONS = 1000
const val SALT = "e0cf1267f564b362"
val KEY_SIZES = listOf(128, 196, 256)

fun main() {
    `AES-CBC-PKCS5Padding should pass`()
    (1..65536).forEach { iterations ->
        if (iterations % 100 == 0) {
            println("Iterations: $iterations")
        }

        KEY_SIZES.forEach { keySize ->
            if (trySalesforceAes(SALT.fromHex(), keySize, iterations).isSuccess) {
                println("ERMAHGERD, FOUND THE SOLUTION!!!1! Salt: HEX, Size: $keySize iterations: $iterations")
                return
            }
            if (trySalesforceAes(SALT.toByteArray(), keySize, iterations).isSuccess) {
                println("ERMAHGERD, FOUND THE SOLUTION!!!1! Salt: BA, Size: $keySize iterations: $iterations")
                return
            }
        }
    }
}

fun `AES-CBC-PKCS5Padding should pass`() {
    val plainText = "Hello World AES, Welcome to Cryptography!"
    val secretKey = getAESKey(AES_KEY_BIT_SIZE)
    val iv = getRandomIV()

    val encryptedText = doEncrypt(secretKey, plainText, iv)
    val decryptedText = decryptWithPrefixIV(encryptedText, secretKey)
    check(decryptedText == plainText)
}

fun `AES-CBC-PKCS5Padding (Salesforce) should pass`() {
    trySalesforceAes(SALT.toByteArray(), AES_KEY_BIT_SIZE, ITERATIONS).getOrThrow()
}

private fun trySalesforceAes(salt: ByteArray, keySize: Int, iterationCount: Int) = runCatching {
    val plainText = "limedash"
    val password = "fresh"
    val iv = "4963b7334a46352623252955df21d7f3".fromHex()
    val cipherText = "4fKWdv7fJRkFsYO6RRtrMg==".fromBase64()

    // The trick is block size 16, key size 32, pbkdf2 with 1000 iterations and padding pkcs7
    val secretKey = getAESKey(password, salt, keySize, iterationCount)
    val encryptedText = doEncrypt(secretKey, plainText, iv)
    val cipherTextWithIv = AesEncoder.concat(iv, cipherText)
    print("Expected  (base64)", cipherText.toBase64())
    check(encryptedText.contentEquals(cipherTextWithIv))

    val decryptedText = decryptWithPrefixIV(encryptedText, secretKey)
    print("Decrypted (plain text)", decryptedText)
    check(decryptedText == plainText)
}

private fun doEncrypt(secretKey: SecretKey, plainText: String, iv: ByteArray): ByteArray {
    val encryptedText = encrypt(plainText, secretKey, iv)
    print(plainText, secretKey, iv, encryptedText)
    return encryptedText
}

private fun print(
    plainText: String,
    secretKey: SecretKey,
    iv: ByteArray,
    encryptedText: ByteArray
) {
    print("Input     (plain text)", plainText)
    print("Key       (hex)", secretKey.encoded.toHex())
    print("IV        (hex)", iv.toHex())
    print("Encrypted (hex)", encryptedText.toHex())
    print("Key       (base64)", secretKey.encoded.toBase64())
    print("IV        (base64)", iv.toBase64())
    print("Encrypted (base64)", encryptedText.toBase64())
}

fun print(vararg args: Any) {
//    println(String.format("%-30s: %s", *args))
}

fun ByteArray.toHex(): String = buildString {
    this@toHex.forEach { append(String.format("%02x", it)) }
}

fun String.fromHex() = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

fun ByteArray.toBase64(): String = Base64.getEncoder().encodeToString(this)

fun String.fromBase64(): ByteArray = Base64.getDecoder().decode(this)
