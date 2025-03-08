package net.its26;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Optional;
import java.security.SecureRandom;


final class Pair<F,L>
{
    public final F first;
    public final L last;

    public Pair(F first, L last)
    {
        assert(first != null);
        assert(last != null);
        this.first = first;
        this.last = last;
    }

    @SuppressWarnings("rawtypes")
    @Override
    public boolean equals(Object other)
    {
        if (this == other)
        {
            return true;
        }

        boolean ret = false;

        if (other instanceof Pair)
        {
            Pair o = (Pair)other;
            ret = (o.first.equals(first)) && (o.last.equals(last));
        }

        return ret;
    }

    @Override
    public int hashCode()
    {
        return first.hashCode() + last.hashCode();
    }
}

public final class RSA 
{
    private static final long MAX_BITS_PRIME_FACTORIZATION = 20;
    private static final ArrayList<Integer> FIRST_PRIMES = calculateFirstPrimes();

    private RSA() {} // no instantiation

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
            if (isOdd(exponent))
            {
                result = result.multiply(base).mod(modulus);
            }

            base = base.multiply(base).mod(modulus);
            exponent = exponent.divide(BigInteger.TWO);
        }

        return result;
    }

    public static BigInteger gcd(BigInteger a, BigInteger b)
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
        if (!isOdd(n))
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
                BigInteger a = getRandom(BigInteger.TWO, n.subtract(BigInteger.TWO));
                BigInteger y = squareAndMultiplyModulus(a, r, n);

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
            ret = generatePrimeSmall(k);
        }
        else
        {
            long B = (long)(0.1 * k * k); // trial division boundary for 4k bits ~16*10^6/10; 1.6Mio

            double r = generateSizeQRelativeN(k);
            // q := ProvablePrimeMaurer(floor(r * k) + 1)
            BigInteger q = provablePrimeMaurer(((long)Math.floor(r * k)) + 1);
            // I := floor(2^(k - 1)/2q)
            BigInteger I = 
                squareAndMultiply(BigInteger.TWO, BigInteger.valueOf(k - 1))
                .divide(BigInteger.TWO.multiply(q));

            boolean success = false;
            while (!success)
            {
                // random value in the range [I+1, 2*I]
                BigInteger R = getRandom(I.add(BigInteger.ONE), I.multiply(BigInteger.TWO));
                // n := 2*R*q + 1
                BigInteger n = BigInteger.TWO.multiply(R).multiply(q).add(BigInteger.ONE);
                
                boolean nNotDivisibleUptoB = checkPrimeUpToLimit(n, B);

                if (nNotDivisibleUptoB)
                {
                    // a := random in [2, n-2]
                    BigInteger a = getRandom(BigInteger.TWO, n.subtract(BigInteger.TWO));
                    // b:= a^(n-1) mod n
                    BigInteger b = squareAndMultiplyModulus(a, n.subtract(BigInteger.ONE), n);

                    if (b.equals(BigInteger.ONE))
                    {
                        // b := a^(2R) mod n
                        b = squareAndMultiplyModulus(a, BigInteger.TWO.multiply(R), n);
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

    private static BigInteger generatePrimeSmall(long k)
    {
        assert(k > 1);
        assert(k < MAX_BITS_PRIME_FACTORIZATION);

        BigInteger min = BigInteger.ONE.shiftLeft((int)k - 1);
        BigInteger max = min.shiftLeft(1).subtract(BigInteger.ONE);

        // FIXME: Since we have already generated all primes with
        // 1..k bits, we simply have to pick a random index in the
        // generated primes array and pick the element!
        while (true)
        {
            BigInteger random = getRandom(min, max);
            long rnd = random.intValue();

            if (isSmallPrime(rnd))
            {
                return BigInteger.valueOf(rnd);
            }
        }
    }

    public static boolean isSmallPrime(long val)
    {
        boolean ret = false;
        assert(val <= FIRST_PRIMES.get(FIRST_PRIMES.size() - 1).longValue());

        for (Integer smallPrime : FIRST_PRIMES)
        {
            if (smallPrime.longValue() == val)
            {
                ret = true;
                break;
            }
        }

        return ret;
    }

    public static boolean checkPrimeUpToLimit(BigInteger val, long checkLimit)
    {
        boolean isPrime = false;

        if (isOdd(val))
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

    // gets a random BigInteger in the (closed) range [min, max]
    private static BigInteger getRandom(BigInteger min, BigInteger max)
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

    private static Optional<Pair<BigInteger, BigInteger>> getSAndR(BigInteger n)
    {
        Optional<Pair<BigInteger, BigInteger>> ret = Optional.empty();

        int s = 1;
        BigInteger twoExpS = BigInteger.TWO;
        while (twoExpS.compareTo(n) <= 0)
        {
            BigInteger divAndRemaind[] = n.divideAndRemainder(twoExpS);
            if (divAndRemaind[1].equals(BigInteger.ZERO) && isOdd(divAndRemaind[0]))
            {
                ret = Optional.of(new Pair<>(BigInteger.valueOf(s), divAndRemaind[0]));
                break;
            }

            s++;
            twoExpS = twoExpS.multiply(BigInteger.TWO);
        }

        return ret;
    }

    private static boolean isOdd(BigInteger val)
    {
        return (val.and(BigInteger.ONE).equals(BigInteger.ONE));
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
