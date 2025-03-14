package net.its26;

import java.math.BigInteger;

public class DSA 
{
    public static class PubKey
    {
        public final BigInteger p;
        public final BigInteger q;
        public final BigInteger alpha;
        public final BigInteger y;

        public PubKey(BigInteger p, BigInteger q, BigInteger alpha, BigInteger y)
        {
            this.p = p;
            this.q = q;
            this.alpha = alpha;
            this.y = y;
        }
    }

    public static class KeyPair
    {
        public final PubKey publicKey;
        public final BigInteger privateKey;

        public KeyPair(PubKey publicKey, BigInteger privateKey)
        {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

    }

    public static KeyPair generateKeyPair(int l)
    {
        Pair<BigInteger, BigInteger> pAndQ = generateNISTPrimes(l);
        BigInteger p = pAndQ.first;
        BigInteger q = pAndQ.last;
        BigInteger alpha = findGenerator(p, q);
        BigInteger a = Common.getRandom(BigInteger.ONE, q.subtract(BigInteger.ONE));
        BigInteger y = Common.squareAndMultiplyModulus(alpha, a, p);

        return new KeyPair(new PubKey(p,q,alpha,y),a);
    }


    // finds a generator for a cyclic group of order q in Z_p*.
    // preconditions: q|(p-1)
    public static BigInteger findGenerator(BigInteger p, BigInteger q)
    {
        assert(p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO));
        // quotient = (p-1)/q
        BigInteger quotient = p.subtract(BigInteger.ONE).divide(q);

        BigInteger alpha = BigInteger.ONE;
        while (alpha.equals(BigInteger.ONE))
        {
            BigInteger g = Common.getRandom(BigInteger.ONE, p.subtract(BigInteger.ONE));
            alpha = Common.squareAndMultiplyModulus(g, quotient, p);
        }

        return alpha;
    }

    public static Pair<BigInteger, BigInteger> generateNISTPrimes(int l)
    {
        int L = 512 + 64 * l;
        int n = (L - 1) / 160;
        int b = (L - 1) % 160;
        assert((L - 1) == 160 * n + b); 
        int g = 160; // bit length of seed
        BigInteger twoExpG = BigInteger.ONE.shiftLeft(g);

        BigInteger seedMin = twoExpG.shiftRight(1); // 2 ^ (g - 1)
        BigInteger seedMax = twoExpG.subtract(BigInteger.ONE); // (2 ^ g) - 1
        assert(seedMin.bitLength() == 160);
        assert(seedMax.bitLength() == 160);
        while (true)
        {
            Pair<BigInteger, BigInteger> sAndQ = getSAndQ(seedMin, seedMax, g);
            BigInteger s = sAndQ.first;
            BigInteger q = sAndQ.last;
    
            int j = 2;
            for (int i = 0; i < 4096; i++)
            {
                BigInteger[] V = new BigInteger[(int)(n + 1)];
                for (int k = 0; k <= n; k++)
                {
                    BigInteger tmp = s.add(BigInteger.valueOf(j).add(BigInteger.valueOf(k))).mod(twoExpG);
                    V[k] = new BigInteger(1, SHA1.sha1(tmp.toByteArray()));
                }
    
                BigInteger W = V[0];
                for (int vIdx = 1; vIdx < n; vIdx++)
                {
                    W = W.add(V[vIdx].shiftLeft(vIdx * 160));
                }
                
                W = W.add(V[n].mod(BigInteger.ONE.shiftLeft(b)).shiftLeft(160 * n));
    
                BigInteger twoExpLMinusOne = BigInteger.ONE.shiftLeft(L - 1);
                BigInteger X = W.add(twoExpLMinusOne);
                BigInteger c = X.mod(q.multiply(BigInteger.TWO));
                BigInteger p = X.subtract(c.subtract(BigInteger.ONE));
    
                if (p.compareTo(twoExpLMinusOne) >= 0)
                {
                    if (RSA.testMillerRabin(p, 5))
                    {
                        return new Pair<>(p, q);
                    }
                }
    
                j = j + n + 1;
            }    
        }
    }

    private static Pair<BigInteger, BigInteger> getSAndQ(BigInteger seedMin, BigInteger seedMax, int g)
    {
        boolean foundPrime = false;
        BigInteger s = null;
        BigInteger q = null;
        while (!foundPrime)
        {
            // Random seed of length 160 bit
            s = Common.getRandom(seedMin, seedMax);
            // 2 ^ g
            BigInteger twoExpG = BigInteger.ONE.shiftLeft(g);
            // (s + 1) mod 2 ^ g
            BigInteger s1 = s.add(BigInteger.ONE).mod(twoExpG);
    
            BigInteger h_s = new BigInteger(1, SHA1.sha1(s.toByteArray()));
            BigInteger h_s1 = new BigInteger(1, SHA1.sha1(s1.toByteArray()));
    
            BigInteger U = h_s.xor(h_s1);
            q = getQFromU(U, g);
            assert(Common.isOdd(q));

            foundPrime = RSA.testMillerRabin(q, 18);
        }
        
        return new Pair<>(s, q);
    }

    private static BigInteger getQFromU(BigInteger U, int g)
    {
        BigInteger q = U;

        if (!Common.isOdd(q))
        {
            q = q.add(BigInteger.ONE);
        }

        assert(Common.isOdd(q));

        BigInteger t1 = BigInteger.ONE.shiftLeft(g - 1);
        if (t1.and(q).equals(BigInteger.ZERO))
        {
            q = q.add(t1);
        }

        assert(q.compareTo(BigInteger.ONE.shiftLeft(g)) < 0);
        assert(q.compareTo(BigInteger.ONE.shiftLeft(g - 1)) > 0);
        assert(Common.isOdd(q));

        return q;
    }
}
