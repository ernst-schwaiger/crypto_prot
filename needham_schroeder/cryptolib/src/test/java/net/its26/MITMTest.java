package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MITMTest {

    @Test void testMQV()
    {
        try
        {
            Optional<KeyPair> optLongTermAlice = EC.generateKeyPair();
            Optional<KeyPair> optSessionAlice = EC.generateKeyPair();

            assertTrue(optLongTermAlice.isPresent());
            assertTrue(optSessionAlice.isPresent());

            //keys for eve
            Optional<KeyPair> optLongTermEve = EC.generateKeyPair();
            Optional<KeyPair> optSessionEve = EC.generateKeyPair();
            assertTrue(optSessionEve.isPresent());
            assertTrue(optLongTermEve.isPresent());


            Optional<KeyPair> optLongTermBob = EC.generateKeyPair();
            Optional<KeyPair> optSessionBob = EC.generateKeyPair();
            assertTrue(optLongTermBob.isPresent());
            assertTrue(optSessionBob.isPresent());

            KeyPair longTermAlice = optLongTermAlice.get();
            KeyPair sessionAlice = optSessionAlice.get();
            KeyPair longTermBob = optLongTermBob.get();
            KeyPair sessionBob = optSessionBob.get();

            KeyPair longTermEve = optLongTermEve.get();
            KeyPair sessionEve = optSessionEve.get();

            // Paranoia checks
            assertFalse(longTermAlice.equals(sessionAlice));
            assertFalse(longTermBob.equals(sessionBob));
            assertFalse(longTermBob.equals(longTermAlice));
            assertFalse(sessionBob.equals(sessionAlice));
            assertFalse(sessionBob.equals(longTermAlice));
            assertFalse(longTermBob.equals(sessionAlice));

            // Eve tricked Alice and Bob to accept her longterm public key
            //so Alice thinks eves key is from bob
            // and bob thinks eves key is from alice
            ECPoint secretAlice = EC.generateSecret(sessionAlice,
                    (ECPrivateKey)longTermAlice.getPrivate(),
                    (ECPublicKey)sessionEve.getPublic(),
                    (ECPublicKey)longTermEve.getPublic());

            ECPoint secretEvewithAlice = EC.generateSecret(sessionEve,
                    (ECPrivateKey)longTermEve.getPrivate(),
                    (ECPublicKey)sessionAlice.getPublic(),
                    (ECPublicKey)longTermAlice.getPublic());

            // now alice an eve have a shared secret, but alice still thinks she is communicationg with bob



            ECPoint secretBob = EC.generateSecret(sessionBob,
                    (ECPrivateKey)longTermBob.getPrivate(),
                    (ECPublicKey)sessionEve.getPublic(),
                    (ECPublicKey)longTermEve.getPublic());

            ECPoint secretEvewithBob = EC.generateSecret(sessionEve,
                    (ECPrivateKey)longTermEve.getPrivate(),
                    (ECPublicKey)sessionBob.getPublic(),
                    (ECPublicKey)longTermBob.getPublic());

            // now Eve has a shred key with bob, but bob thinks he has the shared secret with alice

            assertTrue(secretAlice.equals(secretEvewithAlice));
            assertTrue(secretBob.equals(secretEvewithBob));



            Optional<byte[]> optDigest = EC.getSHA256(secretAlice);
            assertTrue(optDigest.isPresent());
            assertTrue(optDigest.get().length * 8 == 256);
        }
        catch(Exception e)
        {
            fail("MQV Key exchange failed");
        }
    }

    @Test void testIntercept()
    {
        KeyPair longTermAlice = EC.generateKeyPair().get();
        KeyPair sessionAlice = EC.generateKeyPair().get();

        KeyPair longTermBob = EC.generateKeyPair().get();
        KeyPair sessionBob = EC.generateKeyPair().get();
        
        System.out.println("Alice sends her public session key A to Bob...");
        MQV.printByteArray(MQV.serializePubKey(getPublicKey(sessionAlice.getPublic())));

        System.out.println("...but Eve intercepts it and replaces it by her own public key A'...");
        KeyPair sessionEve = EC.generateKeyPair().get();
        MQV.printByteArray(MQV.serializePubKey(getPublicKey(sessionEve.getPublic())));

        System.out.println("...and Bob sends his public session Key back to Alice (and Eve)...");
        MQV.printByteArray(MQV.serializePubKey(getPublicKey(sessionBob.getPublic())));

        System.out.println("Alice and Bob calculate their secrets (Bob uses A', which he got from Eve)...");

        ECPoint secretAlice = EC.generateSecret(sessionAlice,
        (ECPrivateKey)longTermAlice.getPrivate(),
        (ECPublicKey)sessionBob.getPublic(),
        (ECPublicKey)longTermBob.getPublic());

        ECPoint secretBob = EC.generateSecret(sessionBob,
        (ECPrivateKey)longTermBob.getPrivate(),
        (ECPublicKey)sessionEve.getPublic(),
        (ECPublicKey)longTermAlice.getPublic());
        
        System.out.println("Alice's secret:");
        MQV.printByteArray(MQV.serializePubKey(secretAlice));

        System.out.println("Bob's secret:");
        MQV.printByteArray(MQV.serializePubKey(secretBob));

        System.out.println("Bob uses his secret to generate an AES key and to send a secret message to Alice");
        byte[] digestBob = EC.getSHA256(secretBob).get();
        SecretKey aesKeyBob = new SecretKeySpec(digestBob, "AES");
        Optional<Pair<byte[], byte[]>> bobsIVAndCiphertext = encrypt("This is very secret".getBytes(), aesKeyBob);
        System.out.println("Bobs IV:");
        MQV.printByteArray(bobsIVAndCiphertext.get().first);
        System.out.println("Bobs Ciphertext:");
        MQV.printByteArray(bobsIVAndCiphertext.get().last);

        System.out.println("...which Alice can't decipher and Eve records for a later point in time...");
        System.out.println("...sometimes in the future, Eve steals the private Key of Alice and is able to decrypt Bobs message...");

        ECPoint secretEve = EC.generateSecret(sessionEve, // generated by Eve
        (ECPrivateKey)longTermAlice.getPrivate(), // stolen from Alice
        (ECPublicKey)sessionBob.getPublic(), // eavesdropped 
        (ECPublicKey)longTermBob.getPublic()); // publicly known.

        System.out.println("Eves Secret:");
        MQV.printByteArray(MQV.serializePubKey(secretEve));
        byte[] digestEve = EC.getSHA256(secretEve).get();
        SecretKey aesKeyEve = new SecretKeySpec(digestEve, "AES");
        
        String evesCleartext = new String(decrypt(bobsIVAndCiphertext.get().last, bobsIVAndCiphertext.get().first, aesKeyEve).get());
        System.out.println("Eves Clear Text: " + evesCleartext);
    }

    ECPoint getPublicKey(PublicKey pubKey)
    {
        ECPublicKey ecPubKey = (ECPublicKey)pubKey;
        return ecPubKey.getW();
    }

    private Optional<Pair<byte[], byte[]>> encrypt(byte plainText[], SecretKey key)
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
