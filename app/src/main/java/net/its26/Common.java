package net.its26;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

// Commonly used methods
public class Common 
{
    // https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    public static BigInteger getInverse(BigInteger a, BigInteger modulus)
    {
        ArrayList<BigInteger> rs = new ArrayList<>(Arrays.asList(a, modulus));
        ArrayList<BigInteger> ss = new ArrayList<>(Arrays.asList(BigInteger.ONE, BigInteger.ZERO));
        ArrayList<BigInteger> ts = new ArrayList<>(Arrays.asList(BigInteger.ZERO, BigInteger.ONE));

        while (rs.getLast().compareTo(BigInteger.ZERO) > 0)
        {
            BigInteger rq[] = rs.get(rs.size() - 2).divideAndRemainder(rs.getLast());
            BigInteger q = rq[0];
            BigInteger r = rq[1];
            BigInteger s = ss.get(ss.size() - 2).subtract(ss.getLast().multiply(q));
            BigInteger t = ts.get(ts.size() - 2).subtract(ts.getLast().multiply(q));
            rs.add(r);
            ss.add(s);
            ts.add(t);
        }

        BigInteger inverse = ss.get(ss.size() - 2);

        return (inverse.compareTo(BigInteger.ZERO) < 0) ? inverse.add(modulus) : inverse;
    }    

    public static BigInteger squareAndMultiply(BigInteger base, BigInteger exponent)
    {
        BigInteger result = BigInteger.ONE;

        while (exponent.bitCount() > 0)
        {
            if (exponent.and(BigInteger.ONE).equals(BigInteger.ONE))
            {
                result = result.multiply(base);
            }

            base = base.multiply(base);
            exponent = exponent.divide(BigInteger.TWO);
        }

        return result;
    }

    public static BigInteger squareAndMultiplyModulus(BigInteger base, BigInteger exponent, BigInteger modulus)
    {
        BigInteger result = BigInteger.ONE;

        while (exponent.bitCount() > 0)
        {
            if (Common.isOdd(exponent))
            {
                result = result.multiply(base).mod(modulus);
            }

            base = base.multiply(base).mod(modulus);
            exponent = exponent.divide(BigInteger.TWO);
        }

        return result;
    }

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
