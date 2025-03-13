package net.its26;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

// Commonly used methods
public class Common 
{

    // gets a random BigInteger in the (closed) range [min, max]
    public static BigInteger getRandom(BigInteger min, BigInteger max)
    {
        assert(min.compareTo(max) <= 0);
        SecureRandom rnd = new SecureRandom();
        BigInteger range = max.subtract(min);
        int numRndBits = range.bitLength();
        BigInteger ret = new BigInteger(numRndBits, rnd);

        while (ret.compareTo(range) > 0)
        {
            ret = new BigInteger(numRndBits, rnd);
        }

        return ret.add(min);
    }

    public static boolean isOdd(BigInteger val)
    {
        return (val.and(BigInteger.ONE).equals(BigInteger.ONE));
    }

    public static byte[] concat(byte first[], byte last[])
    {
        byte ret[] = new byte[first.length + last.length];
        System.arraycopy(first, 0, ret, 0, first.length);
        System.arraycopy(last, 0, ret, first.length, last.length);
        return ret;
    }
    
    public static byte[] intTo4ByteArrayLE(int i)
    {
        byte ret[] = new byte[4];
        ret[0]=(byte)((i >> 24) & 0xff);
        ret[1]=(byte)((i >> 16) & 0xff);
        ret[2]=(byte)((i >> 8) & 0xff);
        ret[3]=(byte)(i & 0xff);
        return ret;   
    }

    public static byte[] longTo4ByteArrayBE(long in)
    {
        byte ret[] = new byte[4];
        ret[0] = (byte)((in >> 24) & 0xff);
        ret[1] = (byte)((in >> 16) & 0xff);
        ret[2] = (byte)((in >> 8) & 0xff);
        ret[3] = (byte)(in & 0xff);
        return ret;
    }

    public static byte[] longTo8ByteArrayBE(long in)
    {
        byte ret[] = new byte[8];
        Arrays.fill(ret, (byte)0x00);

        int idx = 7;
        while (in != 0)
        {
            ret[idx] = (byte)(in & 0xff);
            idx--;
            in = (in >> 8);
        }

        return ret;
    }
}
