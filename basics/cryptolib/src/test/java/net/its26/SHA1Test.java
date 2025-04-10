package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class SHA1Test 
{
    @Test void testSHA1() 
    {
        // Test against the Java reference implementation
        assertTrue(Arrays.equals(getJavaSHA1Hash("".getBytes()), SHA1.sha1("".getBytes())));
        assertTrue(Arrays.equals(getJavaSHA1Hash("abc".getBytes()), SHA1.sha1("abc".getBytes())));
        assertTrue(Arrays.equals(getJavaSHA1Hash("abcdefghijklmnopqrstuvwxyz".getBytes()), SHA1.sha1("abcdefghijklmnopqrstuvwxyz".getBytes())));
    }

    // This runs the Java SHA-1 as a reference to our implementation
    private byte[] getJavaSHA1Hash(byte data[])
    {
        byte ret[] = null;
        try
        {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(data);
            ret = md.digest();
        }
        catch(NoSuchAlgorithmException e)
        {
            assert(false);
        }

        return ret;
    }

}
