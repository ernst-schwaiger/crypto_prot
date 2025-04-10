package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

public class AESTest 
{
    @Test void generateAESEncryptDecrypt()
    {
        String secretMessage = "Look, Ma, a secret message! And it is long enough so that CBC is used!";
        Optional<SecretKey> optKey = AES.generateKey();
        assertTrue(optKey.isPresent());

        Optional<Pair<byte[], byte[]>> optIVAndCiphertext = AES.encrypt(secretMessage.getBytes(), optKey.get());
        assertTrue(optIVAndCiphertext.isPresent());

        byte iv[] = optIVAndCiphertext.get().first;
        byte cipherText[] = optIVAndCiphertext.get().last;

        Optional<byte[]> optPlainText = AES.decrypt(cipherText, iv, optKey.get());
        assertTrue(optPlainText.isPresent());
        assertTrue(Arrays.equals(optPlainText.get(), secretMessage.getBytes()));
    }    
}
