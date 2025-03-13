package net.its26;

import java.util.Arrays;

public class SHA1 
{
    private static final long h1 = 0x67452301l;
    private static final long h2 = 0xefcdab89l;
    private static final long h3 = 0x98badcfel;
    private static final long h4 = 0x10325476l;
    private static final long h5 = 0xc3d2e1f0l;

    private static final long y1 = 0x5a827999l;
    private static final long y2 = 0x6ed9eba1l;
    private static final long y3 = 0x8f1bbcdcl;
    private static final long y4 = 0xca62c1d6l;

    private static class ABCDE 
    {
        public final long A;
        public final long B;
        public final long C;
        public final long D;
        public final long E;

        public ABCDE(long A, long B, long C, long D, long E)
        {
            this.A = A;
            this.B = B;
            this.C = C;
            this.D = D;
            this.E = E;
        }

        public ABCDE shiftValues(long t)
        {
            return new ABCDE(t, A, rotateLeft(B, 30), C, D);
        }

        @Override
        public boolean equals(Object other)
        {
            if (other == this)
            {
                return true;
            }

            if (other instanceof ABCDE)
            {
                ABCDE o = (ABCDE)other;
                return (A == o.A) && (B == o.B) && (C == o.C) && (D == o.D) && (E == o.E);
            }

            return false;
        }

        @Override
        public int hashCode()
        {
            return (int)((A ^ B ^ C ^ D ^ E) & 0xffffffffl);
        }

        @Override
        public String toString()
        {
            StringBuilder b = new StringBuilder();
            b.append("0x").append(Long.toHexString(A)).append(", ");
            b.append("0x").append(Long.toHexString(B)).append(", ");
            b.append("0x").append(Long.toHexString(C)).append(", ");
            b.append("0x").append(Long.toHexString(D)).append(", ");
            b.append("0x").append(Long.toHexString(E));

            return b.toString();
        }

    }

    public static byte[] sha1(byte data[])
    {
        byte padded_data[] = pad(data);
        int m = padded_data.length / 64;

        long H1 = h1;
        long H2 = h2;
        long H3 = h3;
        long H4 = h4;
        long H5 = h5;

        for (int i = 0; i < m; i++)
        {
            long X[] = copyBlock(padded_data, i);
            ABCDE abcde = new ABCDE(H1, H2, H3, H4, H5);

            // Round 1
            for (int j = 0; j < 20; j++)
            {
                long t = (rotateLeft(abcde.A, 5) + f(abcde.B, abcde.C, abcde.D) + abcde.E + X[j] + y1) & 0xffffffffl;
                abcde = abcde.shiftValues(t);
            }

            // Round 2
            for (int j = 20; j < 40; j++)
            {
                long t = (rotateLeft(abcde.A, 5) + h(abcde.B, abcde.C, abcde.D) + abcde.E + X[j] + y2) & 0xffffffffl;
                abcde = abcde.shiftValues(t);
            }

            // Round 3
            for (int j = 40; j < 60; j++)
            {
                long t = (rotateLeft(abcde.A, 5) + g(abcde.B, abcde.C, abcde.D) + abcde.E + X[j] + y3) & 0xffffffffl;
                abcde = abcde.shiftValues(t);
            }

            // Round 4
            for (int j = 60; j < 80; j++)
            {
                long t = (rotateLeft(abcde.A, 5) + h(abcde.B, abcde.C, abcde.D) + abcde.E + X[j] + y4) & 0xffffffffl;
                abcde = abcde.shiftValues(t);
            }

            H1 = (long)(H1 + abcde.A);
            H2 = (long)(H2 + abcde.B);
            H3 = (long)(H3 + abcde.C);
            H4 = (long)(H4 + abcde.D);
            H5 = (long)(H5 + abcde.E);
        }

        byte tmp[] = Common.concat(Common.longTo4ByteArrayBE(H1), Common.longTo4ByteArrayBE(H2));
        tmp = Common.concat(tmp, Common.longTo4ByteArrayBE(H3));
        tmp = Common.concat(tmp, Common.longTo4ByteArrayBE(H4));
        tmp = Common.concat(tmp, Common.longTo4ByteArrayBE(H5));
        return tmp;
    }

    private static long rotateLeft(long value, int positions) 
    {
        return ((value << positions) | (value >>> (32 - positions))) & 0xffffffffl;
    }

    private static long f(long u, long v, long w)
    {
        return ((u & v) | ((~u) & w)) & 0xffffffffl;
    }

    private static long g(long u, long v, long w)
    {
        return ((u & v) | (u & w) | (v & w)) & 0xffffffffl;
    }

    private static long h(long u, long v, long w)
    {
        return (u ^ v ^ w) & 0xffffffffl;
    }

    private static long[] copyBlock(byte data[], int i)
    {
        long ret[] = new long[80];
        int dataIdx = 64 * i;

        for (int destIdx = 0; destIdx < 16; destIdx++)
        {
            long l0 = (data[dataIdx + (4*destIdx) + 3]) & 0xff;
            long l1 = (data[dataIdx + (4*destIdx) + 2] << 8) & 0xff00;
            long l2 = (data[dataIdx + (4*destIdx) + 1] << 16) & 0xff0000;
            long l3 = (data[dataIdx + (4*destIdx) + 0] << 24) & 0xff000000;
            long lsum = l0 + l1 + l2 + l3;
            
            ret[destIdx] = lsum;
        }

        // expansion to 80 byte block
        for (int j = 16; j < 80; j++)
        {
            long tmp = (ret[j-3] ^ ret[j-8] ^ ret[j-14] ^ ret [j-16]) & 0xffffffffl;
            ret[j] = rotateLeft(tmp, 1);
        }

        return ret;
    }

    private static byte[] pad(byte data[])
    {
        // Pad to a bit length of 512 (== byte length of 64)
        int bytesBeyond64 = (data.length % 64);
        int minPadLenToAdd = 9;

        int paddingBytesToAdd = 64 - bytesBeyond64;
        if (paddingBytesToAdd < minPadLenToAdd)
        {
            paddingBytesToAdd += 64;
        }

        byte tmp[] = new byte[data.length + paddingBytesToAdd];
        System.arraycopy(data, 0, tmp, 0, data.length);
        tmp[data.length] = (byte)0x80;
        Arrays.fill(tmp, data.length + 1, tmp.length - 7, (byte)0x00);
        // we assume that our data is not longer than 2^64 bits
        // Java arrays can hold at most 2 ^ 31 - 1 bytes anyways
        // at most 2 ^ 34 - 8 bits are supported. using a long is sufficient here
        byte bAsBEByteArray[] = Common.longTo8ByteArrayBE(data.length * 8);
        System.arraycopy(bAsBEByteArray, 0, tmp, tmp.length - 8, bAsBEByteArray.length);

        return tmp;
    }
}
