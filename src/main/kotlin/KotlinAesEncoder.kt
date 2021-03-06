import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.ParametersWithIV
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.Hex
import java.nio.ByteBuffer
import java.security.SecureRandom

private const val IV_BYTE_SIZE = 16
private const val KEY_BIT_SIZE = 256
private const val ITERATIONS = 1000
private const val ENCRYPT_MODE = 1
private const val DECRYPT_MODE = 2

object KotlinAesEncoder {

    private val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()))

    fun generateIV(): ByteArray =
        ByteArray(IV_BYTE_SIZE).apply(SecureRandom()::nextBytes)

    fun generateKey(keySize: Int = KEY_BIT_SIZE): CipherParameters = buildKey(
        ByteArray(keySize).apply(SecureRandom()::nextBytes).toBase64(),
        ByteArray(IV_BYTE_SIZE).apply(SecureRandom()::nextBytes)
    )

    fun buildKey(
        password: String,
        salt: ByteArray,
        keySize: Int = KEY_BIT_SIZE,
        iterationCount: Int = ITERATIONS
    ): CipherParameters = with(PKCS5S2ParametersGenerator()) {
        init(password.toByteArray(), salt, iterationCount)
        generateDerivedParameters(keySize)
    }

    fun encryptWithPrefixIV(key: CipherParameters, clearText: String, iv: ByteArray = generateIV()): ByteArray =
        concat(iv, encrypt(key, clearText, iv))

    fun encrypt(key: CipherParameters, clearText: String, iv: ByteArray): ByteArray =
        process(ENCRYPT_MODE, key, iv, clearText.toByteArray())

    fun decryptWithPrefixIV(key: CipherParameters, input: ByteArray): String = with(ByteBuffer.wrap(input)) {
        val iv = ByteArray(IV_BYTE_SIZE).also(::get)
        val cipherText = ByteArray(remaining()).also(::get)
        decrypt(key, cipherText, iv)
    }

    fun decrypt(key: CipherParameters, cipherText: ByteArray, iv: ByteArray): String =
        String(process(DECRYPT_MODE, key, iv, cipherText)).trimEnd { it.code == 0 }

    private fun concat(iv: ByteArray, cipher: ByteArray): ByteArray =
        ByteBuffer.allocate(iv.size + cipher.size).put(iv).put(cipher).array()

    private fun process(mode: Int, key: CipherParameters, iv: ByteArray, input: ByteArray) = with(cipher) {
        init(mode == ENCRYPT_MODE, ParametersWithIV(key, iv))
        ByteArray(getOutputSize(input.size)).also {
            doFinal(it, processBytes(input, 0, input.size, it, 0))
        }
    }
}

fun ByteArray.toHex(): String = Hex.toHexString(this)

fun String.fromHex(): ByteArray = Hex.decode(this)

fun ByteArray.toBase64(): String = Base64.toBase64String(this)

fun String.fromBase64(): ByteArray = Base64.decode(this)
