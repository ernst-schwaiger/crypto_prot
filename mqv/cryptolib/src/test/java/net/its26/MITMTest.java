package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

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
}
