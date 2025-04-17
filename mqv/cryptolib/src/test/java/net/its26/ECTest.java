package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Optional;

public class ECTest 
{
    @Test void testMQV()
    {
        try
        {
            Optional<KeyPair> optLongTermAlice = EC.generateKeyPair();
            Optional<KeyPair> optSessionAlice = EC.generateKeyPair();
            assertTrue(optLongTermAlice.isPresent());
            assertTrue(optSessionAlice.isPresent());

            Optional<KeyPair> optLongTermBob = EC.generateKeyPair();
            Optional<KeyPair> optSessionBob = EC.generateKeyPair();
            assertTrue(optLongTermBob.isPresent());
            assertTrue(optSessionBob.isPresent());

            KeyPair longTermAlice = optLongTermAlice.get();
            KeyPair sessionAlice = optSessionAlice.get();
            KeyPair longTermBob = optLongTermBob.get();
            KeyPair sessionBob = optSessionBob.get();

            // Paranoia checks
            assertFalse(longTermAlice.equals(sessionAlice));
            assertFalse(longTermBob.equals(sessionBob));
            assertFalse(longTermBob.equals(longTermAlice));
            assertFalse(sessionBob.equals(sessionAlice));
            assertFalse(sessionBob.equals(longTermAlice));
            assertFalse(longTermBob.equals(sessionAlice));

            ECPoint secretAlice = EC.generateSecret(sessionAlice, 
                (ECPrivateKey)longTermAlice.getPrivate(), 
                (ECPublicKey)sessionBob.getPublic(), 
                (ECPublicKey)longTermBob.getPublic());

            ECPoint secretBob = EC.generateSecret(sessionBob, 
                (ECPrivateKey)longTermBob.getPrivate(), 
                (ECPublicKey)sessionAlice.getPublic(), 
                (ECPublicKey)longTermAlice.getPublic());

            assertTrue(secretAlice.equals(secretBob));

            Optional<byte[]> optDigest = EC.getSHA256(secretAlice);
            assertTrue(optDigest.isPresent());
            assertTrue(optDigest.get().length * 8 == 256);
        }
        catch(Exception e)
        {
            fail("MQV Key exchange failed");
        }
    }
}
