package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

public class HashTest 
{
    @Test void testHashes() 
    {
        String message1 = "Hello, World";
        String message2 = "Hello, World!";

        byte digestMd5_1[] = Hash.md5(message1.getBytes());
        byte digestMd5_2[] = Hash.md5(message2.getBytes());
        assertTrue(digestMd5_1 != null && digestMd5_2 != null);
        assertFalse(Arrays.equals(digestMd5_1, digestMd5_2));

        byte digestSha1_1[] = Hash.sha1(message1.getBytes());
        byte digestSha1_2[] = Hash.sha1(message2.getBytes());
        assertTrue(digestSha1_1 != null && digestSha1_2 != null);
        assertFalse(Arrays.equals(digestSha1_1, digestSha1_2));

        byte digestSha256_1[] = Hash.sha256(message1.getBytes());
        byte digestSha256_2[] = Hash.sha256(message2.getBytes());
        assertTrue(digestSha256_1 != null && digestSha256_2 != null);
        assertFalse(Arrays.equals(digestSha256_1, digestSha256_2));

        byte digestSha512_1[] = Hash.sha512(message1.getBytes());
        byte digestSha512_2[] = Hash.sha512(message2.getBytes());
        assertTrue(digestSha512_1 != null && digestSha512_2 != null);
        assertFalse(Arrays.equals(digestSha512_1, digestSha512_2));
    }    


}
