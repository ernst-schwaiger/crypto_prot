package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;

public class ECTest 
{
    @Test void testECKeyPairGeneration()
    {
        try
        {
            KeyPair keyPair = EC.generateKeyPair();
            assertTrue(keyPair != null);
        }
        catch(Exception e)
        {
            fail("EC key pair generation failed.");
        }
    }
}
