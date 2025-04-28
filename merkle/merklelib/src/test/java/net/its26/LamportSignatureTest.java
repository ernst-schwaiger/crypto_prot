package net.its26;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class LamportSignatureTest
{
    @Test void testOneTimeSignature() throws NoSuchAlgorithmException
    {
        String myMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgang.";
        String fakedMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgbng.";

        LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair();

        byte[] signature = keyPair.privateKey.sign(myMessage.getBytes());
        assertTrue(keyPair.publicKey.verifySignature(myMessage.getBytes(), signature));
        assertFalse(keyPair.publicKey.verifySignature(fakedMessage.getBytes(), signature));
    }    
}
