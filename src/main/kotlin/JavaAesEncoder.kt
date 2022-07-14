import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object JavaAesEncoder : AesEncoder<SecretKey> {

    private val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

    override fun buildKey(password: String, salt: ByteArray, keySize: Int, iterationCount: Int): SecretKey =
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize))
            .let { SecretKeySpec(it.encoded, "AES") }

    override fun process(mode: Int, key: SecretKey, iv: ByteArray, input: ByteArray): ByteArray = with(cipher) {
        init(mode, key, IvParameterSpec(iv))
        doFinal(input)
    }
}
