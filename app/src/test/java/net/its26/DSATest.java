package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

public class DSATest 
{
    
    @Test void generatePQTest()
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

            BigInteger alpha = DSA.findGenerator(p, q);
            assertTrue(alpha != null);
        }
    }

    @Test void findGeneratorTest()
    {
        // q | (p-1)
        BigInteger p1 = BigInteger.valueOf(19);
        BigInteger q1 = BigInteger.valueOf(3);
        BigInteger g1 = DSA.findGenerator(p1, q1);
        assertTrue(g1 != null);
        assertTrue(BigInteger.ONE.equals(Common.squareAndMultiplyModulus(g1, q1, p1)));

        BigInteger p2 = BigInteger.valueOf(53);
        BigInteger q2 = BigInteger.valueOf(13);
        BigInteger g2 = DSA.findGenerator(p2, q2);
        assertTrue(g2 != null);
        assertTrue(BigInteger.ONE.equals(Common.squareAndMultiplyModulus(g2, q2, p2)));
    }    

}
