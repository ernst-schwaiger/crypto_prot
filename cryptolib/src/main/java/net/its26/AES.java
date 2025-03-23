package net.its26;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

// Encrypts and decrypts in AES 128 CBC
public class AES 
{
    public static Optional<SecretKey> generateKey()
    {
        Optional<SecretKey> ret = Optional.empty();

        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // AES key size
            ret = Optional.of(keyGen.generateKey());    
        }
        catch (NoSuchAlgorithmException e)
        {
        }

        return ret;
    }

    public static Optional<Pair<byte[], byte[]>> encrypt(byte plainText[], SecretKey key)
    {
        Optional<Pair<byte[], byte[]>> ret = Optional.empty();

        try
        {
            byte iv[] = new byte[16]; // 16 bytes for AES
            new SecureRandom().nextBytes(iv); // Secure random IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte ciphertext[] = cipher.doFinal(plainText);

            ret = Optional.of(new Pair<>(iv, ciphertext));
        }
        catch (GeneralSecurityException e)
        {
        }

        return ret;
    }

    public static Optional<byte[]> decrypt(byte cipherText[], byte iv[], SecretKey key)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(cipherText);
            ret = Optional.of(decryptedBytes);
        }
        catch (GeneralSecurityException e)
        {
        }

        return ret;
    }
}
