package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class LamportSignatureTest
{
    @Test void testOneTimeSignature()
    {
        String myMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgang.";
        String fakedMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgbng.";

        LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair(Common.HASH_FUNC_SHA256);

        byte[] signature = keyPair.privateKey.sign(myMessage.getBytes());
        assertTrue(keyPair.publicKey.verifySignature(myMessage.getBytes(), signature));
        assertFalse(keyPair.publicKey.verifySignature(fakedMessage.getBytes(), signature));
    }

    @Test void testOneTimeSignatureWithAlternativeHash()
    {
        String myMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgang.";
        LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair(Common.HASH_FUNC_DUMB);

        byte[] signature = keyPair.privateKey.sign(myMessage.getBytes());
        assertTrue(keyPair.publicKey.verifySignature(myMessage.getBytes(), signature));
    }
}
