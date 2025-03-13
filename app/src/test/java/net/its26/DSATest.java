package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

public class DSATest 
{
    
    @Test void squareAndMultiply()
    {
        for (int l = 0; l < 9; l++)
        {
            Pair<BigInteger, BigInteger> pAndQ = DSA.generateNISTPrimes(l);
            BigInteger p = pAndQ.first;
            BigInteger q = pAndQ.last;

            assertTrue(RSA.testMillerRabin(p, 18));
            assertTrue(RSA.testMillerRabin(q, 18));
            assertEquals(q.bitLength(), 160);
            assertEquals(p.bitLength(), 512 + 64 * l);

            // Assertions on bit lengths of primes,
            // assert that q|(p-1)
            BigInteger pMinusOne = p.subtract(BigInteger.ONE);
            BigInteger tmp = pMinusOne.divide(q);
            assertTrue(tmp.multiply(q).equals(pMinusOne));
        }
    }

}
