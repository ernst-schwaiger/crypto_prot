package net.its26;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash 
{
    public static byte[] md5(byte message[])
    {
        return hash(message, "MD5");        
    }
    
    public static byte[] sha1(byte message[])
    {
        return hash(message, "SHA-1");        
    }

    public static byte[] sha256(byte message[])
    {
        return hash(message, "SHA-256");        
    }

    public static byte[] sha512(byte message[])
    {
        return hash(message, "SHA-512");        
    }

    private static byte[] hash(byte message[], String hashId)
    {
        MessageDigest md = null;
        byte ret[] = null;
        try
        {
            md = MessageDigest.getInstance(hashId);
            md.update(message);
            ret = md.digest();
        }
        catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }

        return ret;
    }
}
