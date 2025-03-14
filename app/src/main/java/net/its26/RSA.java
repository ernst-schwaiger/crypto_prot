package net.its26;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;
import java.security.SecureRandom;

public final class RSA 
{
    private static final long MAX_BITS_PRIME_FACTORIZATION = 20;
    private static final ArrayList<Integer> FIRST_PRIMES = calculateFirstPrimes();

    private static final byte SINGLE_BYTE_ARRAY_ONE[] = { 1 };

    private RSA() {} // no instantiation

    public static byte[] encrypt(BigInteger key, BigInteger modulus, byte message[])
    {
        BigInteger val = new BigInteger(message);
        BigInteger encrypted = Common.squareAndMultiplyModulus(val, key, modulus);
        byte ret[] = encrypted.toByteArray();
        return ret;
    } 

    public static byte[] decrypt(BigInteger key, BigInteger modulus, byte ciphertext[])
    {
        BigInteger val = new BigInteger(ciphertext);
        BigInteger decrypted = Common.squareAndMultiplyModulus(val, key, modulus);
        byte ret[] = decrypted.toByteArray();
        return ret;
    }

    public static byte[] padAndEncrypt(BigInteger key, BigInteger modulus, byte message[])
    {
        int keyLenByte = (modulus.bitLength() + 7) / 8;       
        byte paddedMessage[] = optimalAsymmetricEncryptionPadding(message, keyLenByte);
        assert(paddedMessage.length == keyLenByte);
        return encrypt(key, modulus, paddedMessage);
    }

    public static byte[] decryptAndUnpad(BigInteger key, BigInteger modulus, byte ciphertext[])
    {
        int keyLenByte = (modulus.bitLength() + 7) / 8;
        byte decryptedAndPadded[] = decrypt(key, modulus, ciphertext);
        byte ret[] = optimalAsymmetricEncryptionUnPadding(decryptedAndPadded, keyLenByte);
        return ret;
    }


    // taken from https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    private static byte[] optimalAsymmetricEncryptionPadding(byte m[], int k)
    {
        final byte lhash[] = padding_hash("".getBytes());
        final int hLen = lhash.length;
        final int PSLen = k - m.length - 2 * hLen - 2;

        byte PS[] = new byte[PSLen];
        Arrays.fill(PS, 0, PSLen, (byte)0x00);

        byte DB[] = Common.concat(Common.concat(Common.concat(lhash, PS), SINGLE_BYTE_ARRAY_ONE), m);
        // Random seed in the range 0..uint32_max
        byte seed[] = Common.intTo4ByteArrayLE(Common.getRandom(BigInteger.ZERO, BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE)).intValue());

        byte dbMask[] = mgf1(seed, DB.length);
        byte maskedDB[] = xor(dbMask, DB);
        byte seedMask[] = mgf1(maskedDB, seed.length);
        byte maskedSeed[] = xor(seed, seedMask);

        byte ret[] = Common.concat(Common.concat(SINGLE_BYTE_ARRAY_ONE, maskedSeed), maskedDB);
        return ret;
    }

    private static byte[] optimalAsymmetricEncryptionUnPadding(byte p[], int k)
    {
        final byte lhash[] = padding_hash("".getBytes());
        final int hLen = lhash.length;

        if (p[0] != SINGLE_BYTE_ARRAY_ONE[0])
        {
            return null;
        }

        byte maskedSeed[] = Arrays.copyOfRange(p, 1, 1 + hLen);
        byte maskedDB[] = Arrays.copyOfRange(p, 1 + hLen, p.length);
        byte seedMask[] = mgf1(maskedDB, hLen);
        byte seed[] = xor(maskedSeed, seedMask);
        byte dbMask[] = mgf1(seed, maskedDB.length);
        byte DB[] = xor(dbMask, maskedDB);

        // extract DB
        byte hash[] = Arrays.copyOfRange(DB, 0, 4);

        if (!Arrays.equals(hash, lhash))
        {
            return null;
        }

        // skip over zero bytes
        int idxPS = hLen + 1;
        while (DB[idxPS] == 0)
        {
            idxPS++;
        }

        if (DB[idxPS] != 1)
        {
            return null;
        }

        byte ret[] = Arrays.copyOfRange(DB, idxPS + 1, DB.length);
        return ret;
    }

    // taken from https://en.wikipedia.org/wiki/Mask_generation_function
    private static byte[] mgf1(byte Z[], int l)
    {
        byte T[] = new byte[0];
        int counter = 0;

        while (T.length < l)
        {
            byte C[] = Common.intTo4ByteArrayLE(counter);
            byte Z_C[] = Common.concat(Z, C);
            T = Common.concat(T, padding_hash(Z_C));
            counter++;
        }

        byte ret[] = new byte[l];
        System.arraycopy(ret, 0, T, 0, l);
        return ret;
    }

    private static byte[] xor(byte first[], byte last[])
    {
        assert(first.length == last.length);
        byte ret[] = new byte[first.length];

        for (int idx = 0; idx < first.length; idx++)
        {
            ret[idx] = (byte)(first[idx] ^ last[idx]);
        }

        return ret;
    }

    private static byte[] padding_hash(byte data[])
    {
        // Do not use data.hashCode() directly, 
        // *it does not give you a hash on the array content!*
        // For now, we are emplyoing a lumberjack function here...

        long hashCode = 0;
        for (int i = 0; i < data.length; i++)
        {
            // remove the signedness, pain in the back
            int tmp = (data[i] & 0x000000ff);
            hashCode += tmp; 
        }

        return Common.intTo4ByteArrayLE((int)hashCode & 0xffffffff);
    }

    // Generates a Private/Publlic Key Pair using two primes p, q of bit length k
    public static Pair<BigInteger, Pair<BigInteger, BigInteger>> generateKeyPair(long k)
    {
        BigInteger p = provablePrimeMaurer(k);
        BigInteger q = provablePrimeMaurer(k);
        BigInteger n = p.multiply(q);

        BigInteger phi_n = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger e = generateE(phi_n);   
        BigInteger d = Common.getInverse(e, phi_n);

        assert(e.multiply(d).mod(phi_n).equals(BigInteger.ONE));

        return new Pair<>(d, new Pair<>(e,n));
    }

    private static BigInteger generateE(BigInteger phi_n)
    {
        int bitLen = phi_n.bitLength();
        int bitlen_min = bitLen / 4;
        int bitlen_max = (bitLen * 3) / 4;

        BigInteger e_min = BigInteger.ONE.shiftLeft(bitlen_min - 1).add(BigInteger.ONE);
        BigInteger e_max = BigInteger.ONE.shiftLeft(bitlen_max - 1).subtract(BigInteger.ONE);

        while (true)
        {
            BigInteger e = Common.getRandom(e_min, e_max);
            if (gcd(phi_n, e).equals(BigInteger.ONE))
            {
                return e;
            }
        }
    }

    // private static BigInteger getInverse(BigInteger a, BigInteger modulus)
    // {
    //     ArrayList<BigInteger> rs = new ArrayList<>(Arrays.asList(a, modulus));
    //     ArrayList<BigInteger> ss = new ArrayList<>(Arrays.asList(BigInteger.ONE, BigInteger.ZERO));
    //     ArrayList<BigInteger> ts = new ArrayList<>(Arrays.asList(BigInteger.ZERO, BigInteger.ONE));

    //     while (rs.getLast().compareTo(BigInteger.ZERO) > 0)
    //     {
    //         BigInteger rq[] = rs.get(rs.size() - 2).divideAndRemainder(rs.getLast());
    //         BigInteger q = rq[0];
    //         BigInteger r = rq[1];
    //         BigInteger s = ss.get(ss.size() - 2).subtract(ss.getLast().multiply(q));
    //         BigInteger t = ts.get(ts.size() - 2).subtract(ts.getLast().multiply(q));
    //         rs.add(r);
    //         ss.add(s);
    //         ts.add(t);
    //     }

    //     BigInteger inverse = ss.get(ss.size() - 2);

    //     return (inverse.compareTo(BigInteger.ZERO) < 0) ? inverse.add(modulus) : inverse;
    // }

    private static BigInteger gcd(BigInteger a, BigInteger b)
    {
        if (a.equals(BigInteger.ZERO))
        {
            return b;
        }

        if (b.equals(BigInteger.ZERO))
        {
            return a;
        }

        return (a.compareTo(b) >= 0) ? gcd2(a, b) : gcd2(b, a);
    }

    // precondition greater >= lesser
    private static BigInteger gcd2(BigInteger greater, BigInteger lesser)
    {
        return (lesser.equals(BigInteger.ZERO)) ? greater : gcd2(lesser, greater.mod(lesser));
    }

    // tests whether the passed value is probably a prime
    // preconditions n >= 5, t >= 1
    public static boolean testMillerRabin(BigInteger n, long t)
    {
        // we only accept positive integers
        assert(n.compareTo(BigInteger.ZERO) > 0);

        // At least one test round is required
        assert(t > 0);

        // Two is the oddest prime
        if (n.equals(BigInteger.TWO))
        {
            return true;
        }

        // Weed out the even numbers in the beginning
        if (!Common.isOdd(n))
        {
            return false;
        }

        boolean greaterOrEqualFive = (n.compareTo(new BigInteger("5")) >= 0);
        // n >= 5 and odd
        if (greaterOrEqualFive)
        {
            BigInteger n_1 = n.subtract(BigInteger.ONE); // n minus one
            Optional<Pair<BigInteger, BigInteger>> optSAndR = getSAndR(n_1);
            assert(optSAndR.isPresent());
            BigInteger s = optSAndR.get().first;
            BigInteger r = optSAndR.get().last;
            for (long i = 0; i < t; i++)
            {
                BigInteger a = Common.getRandom(BigInteger.TWO, n.subtract(BigInteger.TWO));
                BigInteger y = Common.squareAndMultiplyModulus(a, r, n);

                if ((!y.equals(BigInteger.ONE)) && (!y.equals(n_1)))
                {
                    BigInteger j = BigInteger.ONE;
                    
                    // j < s and y != n-1
                    while ((j.compareTo(s) < 0) && (!y.equals(n_1)))
                    {
                        y = y.multiply(y).mod(n); // y := y^2 mod n

                        if (y.equals(BigInteger.ONE))
                        {
                            return false;
                        }

                        j = j.add(BigInteger.ONE);
                    }

                    if (!y.equals(n_1))
                    {
                        return false;
                    }
                }
            }

            return true;
        }
        else // n < 5 and odd and != 2
        {
            // 1, 2, 3 are primes
            return true;
        }       
    }

    // Generate a prime number with the given number of bits k
    public static BigInteger provablePrimeMaurer(long k)
    {
        assert(k > 1);

        BigInteger ret = BigInteger.ONE;
        if (k < MAX_BITS_PRIME_FACTORIZATION)
        {
            ret = getSmallPrime(k);
        }
        else
        {
            long B = (long)(0.1 * k * k); // trial division boundary for 4k bits ~16*10^6/10; 1.6Mio

            double r = generateSizeQRelativeN(k);
            // q := ProvablePrimeMaurer(floor(r * k) + 1)
            BigInteger q = provablePrimeMaurer(((long)Math.floor(r * k)) + 1);
            // I := floor(2^(k - 1)/2q)
            BigInteger I = 
                Common.squareAndMultiply(BigInteger.TWO, BigInteger.valueOf(k - 1))
                .divide(BigInteger.TWO.multiply(q));

            boolean success = false;
            while (!success)
            {
                // random value in the range [I+1, 2*I]
                BigInteger R = Common.getRandom(I.add(BigInteger.ONE), I.multiply(BigInteger.TWO));
                // n := 2*R*q + 1
                BigInteger n = BigInteger.TWO.multiply(R).multiply(q).add(BigInteger.ONE);
                
                boolean nNotDivisibleUptoB = checkPrimeUpToLimit(n, B);

                if (nNotDivisibleUptoB)
                {
                    // a := random in [2, n-2]
                    BigInteger a = Common.getRandom(BigInteger.TWO, n.subtract(BigInteger.TWO));
                    // b:= a^(n-1) mod n
                    BigInteger b = Common.squareAndMultiplyModulus(a, n.subtract(BigInteger.ONE), n);

                    if (b.equals(BigInteger.ONE))
                    {
                        // b := a^(2R) mod n
                        b = Common.squareAndMultiplyModulus(a, BigInteger.TWO.multiply(R), n);
                        // d := gcd(b-1, n)
                        BigInteger d = gcd(b.subtract(BigInteger.ONE), n);

                        if (d.equals(BigInteger.ONE))
                        {
                            success = true;
                            ret = n;
                        }
                    }
                }
            }
        }

        return ret;
    }

    private static double generateSizeQRelativeN(long k)
    {
        final long m = MAX_BITS_PRIME_FACTORIZATION;
        //final double c = 0.1;
        //final double B = c * k * k;

        double r = 0.5;
    
        if (k > 2 * m)
        {
            SecureRandom random = new SecureRandom();
            double s = random.nextDouble();
            while (true)
            {
                r = Math.pow(2.0, s - 1.0);
                if ((k - (r * k)) > m)
                {
                    break;
                }
                s = random.nextDouble();
            }
        }

        return r;
    }

    private static BigInteger getSmallPrime(long k)
    {
        assert(k > 1);
        assert(k < MAX_BITS_PRIME_FACTORIZATION);

        int min = 1 << (k - 1);

        int minIdx = Collections.binarySearch(FIRST_PRIMES, Integer.valueOf(min));
        if (minIdx < 0)
        {
            minIdx = (minIdx + 1) * - 1;
        }

        int max = (min << 1) - 1;
        int maxIdx = Collections.binarySearch(FIRST_PRIMES, Integer.valueOf(max));
        if (maxIdx < 0)
        {
            maxIdx = (maxIdx + 1) * - 1;
            if (maxIdx >= FIRST_PRIMES.size())
            {
                maxIdx = FIRST_PRIMES.size() - 1;
            }
        }

        int randomIdx = Common.getRandom(BigInteger.valueOf(minIdx), BigInteger.valueOf(maxIdx)).intValue();
        return BigInteger.valueOf(FIRST_PRIMES.get(randomIdx).intValue());
    }

    private static boolean checkPrimeUpToLimit(BigInteger val, long checkLimit)
    {
        boolean isPrime = false;

        if (Common.isOdd(val))
        {
            BigInteger squareRoot = val.sqrt();
            checkLimit = (squareRoot.compareTo(BigInteger.valueOf(checkLimit)) < 0 ) ? squareRoot.longValue() : checkLimit;
            isPrime = true;
            for (Integer div : FIRST_PRIMES)
            {
                if (div.longValue() > checkLimit)
                {
                    break;
                }

                BigInteger tmp = val.divide(BigInteger.valueOf(div));

                if (tmp.multiply(BigInteger.valueOf(div)).equals(val))
                {
                    isPrime = false;
                    break;
                }
            }
        }
        else if (val.equals(BigInteger.TWO)) // Two is the oddest prime
        {
            isPrime = true;
        }
        
        return isPrime;
    }

    private static Optional<Pair<BigInteger, BigInteger>> getSAndR(BigInteger n)
    {
        Optional<Pair<BigInteger, BigInteger>> ret = Optional.empty();

        int s = 1;
        BigInteger twoExpS = BigInteger.TWO;
        while (twoExpS.compareTo(n) <= 0)
        {
            BigInteger divAndRemaind[] = n.divideAndRemainder(twoExpS);
            if (divAndRemaind[1].equals(BigInteger.ZERO) && Common.isOdd(divAndRemaind[0]))
            {
                ret = Optional.of(new Pair<>(BigInteger.valueOf(s), divAndRemaind[0]));
                break;
            }

            s++;
            twoExpS = twoExpS.multiply(BigInteger.TWO);
        }

        return ret;
    }

    private static ArrayList<Integer> calculateFirstPrimes()
    {
        int max = (1 << MAX_BITS_PRIME_FACTORIZATION) - 1;

        ArrayList<Integer> ret = new ArrayList<>(82025);
        for (int i = 2; i <= max; i++)
        {
            if (isPrimeExhaustive(i))
            {
                ret.add(Integer.valueOf(i));
            }
        }

        return ret;
    }

    private static boolean isPrimeExhaustive(long val)
    {
        boolean isPrime = false;

        if (val % 2 == 1)
        {
            isPrime = true;
            for (long div = 3; div * div <= val; div += 2)
            {
                long tmp = val / div;

                if (tmp * div == val)
                {
                    isPrime = false;
                    break;
                }
            }
        }
        else if (val == 2) // Two is the oddest prime
        {
            isPrime = true;
        }
        
        return isPrime;
    }    
}
