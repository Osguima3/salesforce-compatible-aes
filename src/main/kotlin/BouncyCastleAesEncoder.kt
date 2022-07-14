import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.ParametersWithIV

private const val ENCRYPT_MODE = 1

object BouncyCastleAesEncoder : AesEncoder<CipherParameters> {

    private val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()))

    override fun buildKey(password: String, salt: ByteArray, keySize: Int, iterationCount: Int): CipherParameters =
        with(PKCS5S2ParametersGenerator()) {
            init(password.toByteArray(), salt, iterationCount)
            generateDerivedParameters(keySize)
        }

    override fun process(mode: Int, key: CipherParameters, iv: ByteArray, input: ByteArray) = with(cipher) {
        init(mode == ENCRYPT_MODE, ParametersWithIV(key, iv))
        ByteArray(getOutputSize(input.size)).also {
            doFinal(it, processBytes(input, 0, input.size, it, 0))
        }
    }
}
