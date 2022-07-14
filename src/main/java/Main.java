import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;
import java.util.Objects;

public class Main {

    public static void main(String[] args) {
        System.out.println("----Random generated key + IV-----");
        runTest(
            JavaAesEncoder.generateKey(),
            JavaAesEncoder.generateIV(),
            "Hello World AES, Welcome to Cryptography!",
            null
        );

        System.out.println("----Random generated key + IV, embedded IV-----");
        runTestWithPrefixIv(
            JavaAesEncoder.generateKey(),
            JavaAesEncoder.generateIV(),
            "Hello World AES, Welcome to Cryptography!"
        );

        System.out.println("----Salesforce provided example (https://ampscript.guide/encryptsymmetric)-----");
        runTest(
            JavaAesEncoder.buildKey(
                "fresh",
                Hex.decode("e0cf1267f564b362")
            ),
            Hex.decode("4963b7334a46352623252955df21d7f3"),
            "limedash",
            Base64.decode("4fKWdv7fJRkFsYO6RRtrMg==")
        );
    }

    private static void runTest(CipherParameters key, byte[] iv, String clearText, byte[] expectedEncryptedText) {
        try {
            byte[] encryptedText = JavaAesEncoder.encrypt(key, clearText, iv);
            String decryptedText = JavaAesEncoder.decrypt(key, encryptedText, iv);
            Assert(clearText, iv, encryptedText, decryptedText, expectedEncryptedText);
        } catch (Exception e) {
            assert false;
        }
    }

    private static void runTestWithPrefixIv(CipherParameters key, byte[] iv, String clearText) {
        try {
            byte[] encryptedText = JavaAesEncoder.encryptWithPrefixIV(key, clearText, iv);
            String decryptedText = JavaAesEncoder.decryptWithPrefixIV(key, encryptedText);

            Assert(clearText, iv, encryptedText, decryptedText, null);
        } catch (Exception e) {
            assert false;
        }
    }

    private static void Assert(
        String clearText,
        byte[] iv,
        byte[] encryptedText,
        String decryptedText,
        byte[] expectedEncryptedText
    ) {
        print("Input     (plain text)", clearText);
        print("IV        (hex)", Hex.toHexString(iv));
        print("Encrypted (hex)", Hex.toHexString(encryptedText));
        print("IV        (base64)", Base64.toBase64String(iv));
        print("Encrypted (base64)", Base64.toBase64String(encryptedText));
        if (expectedEncryptedText != null) print("Expected  (base64)", Base64.toBase64String(expectedEncryptedText));
        print("Decrypted (plain text)", decryptedText);

        assert expectedEncryptedText == null || Arrays.equals(expectedEncryptedText, encryptedText);
        assert Objects.equals(decryptedText, clearText);

        System.out.println();
    }

    private static void print(String text, Object value) {
        System.out.printf("%-30s: %s%n", text, value);
    }
}
