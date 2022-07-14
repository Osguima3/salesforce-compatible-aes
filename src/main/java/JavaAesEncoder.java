import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.bouncycastle.util.encoders.Base64.toBase64String;

public class JavaAesEncoder {

    private static final int IV_BYTE_SIZE = 16;

    private static final int KEY_BIT_SIZE = 256;

    private static final int ITERATIONS = 1000;

    private static final int ENCRYPT_MODE = 1;

    private static final int DECRYPT_MODE = 2;

    private static final PaddedBufferedBlockCipher cipher =
        new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()));

    public static byte[] generateIV() {
        return generateByteArray(IV_BYTE_SIZE);
    }

    public static CipherParameters generateKey() {
        return buildKey(
            toBase64String(generateByteArray(KEY_BIT_SIZE)),
            generateByteArray(IV_BYTE_SIZE)
        );
    }

    private static byte[] generateByteArray(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static CipherParameters buildKey(String password, byte[] salt) {
        PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator();
        generator.init(password.getBytes(), salt, ITERATIONS);
        return generator.generateDerivedParameters(KEY_BIT_SIZE);
    }

    public static byte[] encryptWithPrefixIV(CipherParameters key, String clearText, byte[] iv) throws Exception {
        return concat(iv, encrypt(key, clearText, iv));
    }

    public static byte[] encrypt(CipherParameters key, String clearText, byte[] iv) throws Exception {
        return process(ENCRYPT_MODE, key, iv, clearText.getBytes());
    }

    public static String decryptWithPrefixIV(CipherParameters key, byte[] input) throws Exception {
        ByteBuffer buffer = ByteBuffer.wrap(input);

        byte[] iv = new byte[IV_BYTE_SIZE];
        buffer.get(iv);

        byte[] cipherText = new byte[buffer.remaining()];
        buffer.get(cipherText);

        return decrypt(key, cipherText, iv);
    }

    public static String decrypt(CipherParameters key, byte[] cipherText, byte[] iv) throws Exception {
        return new String(process(DECRYPT_MODE, key, iv, cipherText)).replace("\0", "");
    }

    private static byte[] concat(byte[] iv, byte[] cipher) {
        return ByteBuffer.allocate(iv.length + cipher.length).put(iv).put(cipher).array();
    }

    private static byte[] process(int mode, CipherParameters key, byte[] iv, byte[] input) throws Exception {
        cipher.init(mode == ENCRYPT_MODE, new ParametersWithIV(key, iv));
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        cipher.doFinal(output, cipher.processBytes(input, 0, input.length, output, 0));
        return output;
    }
}
