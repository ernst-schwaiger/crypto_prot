package net.its26;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Common 
{
    public static final MessageDigest SHA_256_MD = Common.get256MessageDigest();

    public static MessageDigest get256MessageDigest()
    {
        MessageDigest ret = null;
        try
        {
            ret = MessageDigest.getInstance("SHA-256");
        }
        catch(NoSuchAlgorithmException e)
        {
            System.err.println("Error: Could not retrieve SHA-256 message digest");
            System.exit(1);
        }

        return ret;
    }
    
}
