package net.its26;

import java.math.BigInteger;
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
    
    public static class DumbHash implements IHashFunction
    {
    private static final BigInteger TWO_POW_256 = BigInteger.ONE.shiftLeft(256);
    private static final int HASH_SIZE = 32; 

    /*
      Einfache hashfunktion. Nimmt die Message modulo 256
     */
    @Override
    public byte[] hash(byte[] input) {
        // BigInteger mit positivem Vorzeichen
        BigInteger x = new BigInteger(1, input);
        BigInteger h = x.mod(TWO_POW_256);

        byte[] raw = h.toByteArray();
        byte[] out = new byte[HASH_SIZE];

        if (raw.length == HASH_SIZE + 1 && raw[0] == 0) {
            // wenn zu lang, führende Null-Byte abschneiden
            System.arraycopy(raw, 1, out, 0, HASH_SIZE);
        } else if (raw.length <= HASH_SIZE) {
            // bei kürzerem Array vorne mit Nullen auffüllen
            System.arraycopy(raw, 0, out, HASH_SIZE - raw.length, raw.length);
        } else {
            // die letzten 32 Bytes nehmen falls zu lang
            System.arraycopy(raw, raw.length - HASH_SIZE, out, 0, HASH_SIZE);
        }

        return out;
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
