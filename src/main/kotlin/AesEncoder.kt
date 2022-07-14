import java.nio.ByteBuffer.allocate
import java.nio.ByteBuffer.wrap
import java.security.SecureRandom
import javax.crypto.Cipher

private const val IV_SIZE: Int = 16

interface AesEncoder<Key> {

    fun generateIV(): ByteArray =
        ByteArray(IV_SIZE).apply(SecureRandom()::nextBytes)

    fun generateKey(keySize: Int): Key = buildKey(
        ByteArray(keySize).apply(SecureRandom()::nextBytes).toBase64(),
        ByteArray(IV_SIZE).apply(SecureRandom()::nextBytes)
    )

    fun buildKey(password: String, salt: ByteArray, keySize: Int = 256, iterationCount: Int = 65536): Key

    fun encryptWithPrefixIV(key: Key, plainText: String, iv: ByteArray = generateIV()): ByteArray =
        concat(iv, encrypt(key, plainText, iv))

    fun encrypt(key: Key, plainText: String, iv: ByteArray): ByteArray =
        process(Cipher.ENCRYPT_MODE, key, iv, plainText.toByteArray())

    fun decryptWithPrefixIV(key: Key, input: ByteArray): String = with(wrap(input)) {
        val iv = ByteArray(IV_SIZE).also(::get)
        val cipherText = ByteArray(remaining()).also(::get)
        decrypt(key, cipherText, iv)
    }

    fun decrypt(key: Key, cipherText: ByteArray, iv: ByteArray): String =
        String(process(Cipher.DECRYPT_MODE, key, iv, cipherText)).trimEnd { it.code == 0}

    fun process(mode: Int, key: Key, iv: ByteArray, input: ByteArray): ByteArray

    fun concat(iv: ByteArray, cipher: ByteArray): ByteArray =
        allocate(iv.size + cipher.size).put(iv).put(cipher).array()
}
