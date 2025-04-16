package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

public class ECTest 
{
    @Test void testMQV()
    {
        try
        {
            KeyPair longTermAlice = EC.generateKeyPair();
            KeyPair sessionAlice = EC.generateKeyPair();

            KeyPair longTermBob = EC.generateKeyPair();
            KeyPair sessionBob = EC.generateKeyPair();

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

            byte digest[] = EC.getSHA256(secretAlice);
        }
        catch(Exception e)
        {
            fail("MQV Key exchange failed");
        }

    }
}
