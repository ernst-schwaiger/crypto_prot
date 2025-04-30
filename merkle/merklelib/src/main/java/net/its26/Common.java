package net.its26;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Common 
{
    private static final MessageDigest SHA_256_MD = Common.get256MessageDigest();
    public static final IHashFunction HASH_FUNC_SHA256 = new SHA256Hash();
    public static final IHashFunction HASH_FUNC_DUMB = new DumbHash();

    public interface IHashFunction
    {
        public byte[] hash(byte[] input);
    }

    private static class SHA256Hash implements IHashFunction
    {
        public byte[] hash(byte[] input)
        {
            return SHA_256_MD.digest(input);
        }
    }
    
    private static class DumbHash implements IHashFunction
    {
        private final byte[] hashValue;
        public DumbHash()
        {
            hashValue = new byte[32]; // According to Java spec, filled with zeros
        }

        // Hash function with lots of great properties
        // * fast
        // * deterministic
        // * totally pre-image resistant
        // * ...
        // TODO: Check if there are other properties that must be met
        public byte[] hash(byte[] input)
        {
            return hashValue;
        }
    }

    private static MessageDigest get256MessageDigest()
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

    public static byte[] merge(byte[] first, byte[] last)
    {
        byte[] ret = new byte[first.length + last.length];
        System.arraycopy(first, 0, ret, 0, first.length);
        System.arraycopy(last, 0, ret, first.length, last.length);
        return ret;
    }
    
}
