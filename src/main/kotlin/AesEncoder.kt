import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

private const val IV_SIZE = 16

object AesEncoder {

    fun getRandomIV(): ByteArray =
        ByteArray(IV_SIZE).apply(SecureRandom()::nextBytes)

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

    fun encryptWithPrefixIV(plainText: ByteArray, secret: SecretKey, iv: ByteArray): ByteArray =
        with(encrypt(plainText, secret, iv)) {
            ByteBuffer.allocate(IV_SIZE + size)
                .put(iv).put(this)
                .array()
        }

    fun encrypt(plainText: ByteArray, secret: SecretKey, iv: ByteArray): ByteArray =
        Cipher.getInstance("AES/CBC/PKCS5Padding")
            .apply { init(Cipher.ENCRYPT_MODE, secret, IvParameterSpec(iv)) }
            .doFinal(plainText)

    fun decryptWithPrefixIV(cipherText: ByteArray, secret: SecretKey): String = with(
        ByteBuffer.wrap(cipherText)) {
        val iv = ByteArray(IV_SIZE).also(::get)
        val cipher = ByteArray(remaining()).also(::get)
        decrypt(cipher, secret, iv)
    }

    fun decrypt(cText: ByteArray, secret: SecretKey, iv: ByteArray): String =
        Cipher.getInstance("AES/CBC/PKCS5Padding")
            .apply { init(Cipher.DECRYPT_MODE, secret, IvParameterSpec(iv)) }
            .doFinal(cText)
            .let(::String)

}
