package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

public class HMACTest 
{
    @Test void testHMAC() 
    {
        String message = "Hello, World!";
        String key1 = "MySecret1";
        String key2 = "MySecret2";

        byte hmac1[] = HMAC.hmacSha256(message.getBytes(), key1.getBytes());
        byte hmac2[] = HMAC.hmacSha256(message.getBytes(), key2.getBytes());
        assertTrue(hmac1 != null && hmac2 != null);
        assertFalse(Arrays.equals(hmac1, hmac2));
    }    
}
