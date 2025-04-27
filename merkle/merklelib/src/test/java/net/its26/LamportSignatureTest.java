package net.its26;

import java.security.NoSuchAlgorithmException;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class LamportSignatureTest
{
    @Test void testOneTimeSignature() throws NoSuchAlgorithmException
    {
        LamportSignature lamportSignature = new LamportSignature();
        String myMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgang.";
        String fakedMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgbng.";

        byte[] signature = lamportSignature.privKey.sign(myMessage.getBytes());
        assertTrue(lamportSignature.pubKey.verifySignature(myMessage.getBytes(), signature));
        assertFalse(lamportSignature.pubKey.verifySignature(fakedMessage.getBytes(), signature));
    }    
}
