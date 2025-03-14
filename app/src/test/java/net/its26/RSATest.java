package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;


import java.math.BigInteger;
import java.util.Arrays;

class RSATest {

    @Test void testMillerRabin()
    {
        assertEquals(true, RSA.testMillerRabin(BigInteger.ONE, 10));
        assertEquals(true, RSA.testMillerRabin(BigInteger.TWO, 10));
        assertEquals(true, RSA.testMillerRabin(new BigInteger("3"), 10));
        assertEquals(false, RSA.testMillerRabin(new BigInteger("4"), 10));
        assertEquals(true, RSA.testMillerRabin(new BigInteger("5"), 10));
        assertEquals(true, RSA.testMillerRabin(new BigInteger("9973"), 10));        
    }

    @Test void testGeneratePrimeSmall()
    {
        BigInteger twoBitPrime = RSA.provablePrimeMaurer(2);
        // may only be two or three
        assertTrue(twoBitPrime.equals(BigInteger.TWO) || 
            twoBitPrime.equals(BigInteger.TWO.add(BigInteger.ONE)));

        // probabilistic tests

        BigInteger Prime19BitMin = new BigInteger("262144");
        BigInteger Prime19BitMax = new BigInteger("524287");

        for (long i = 0; i < 100; i++)
        {
            BigInteger prime = RSA.provablePrimeMaurer(19);
            assertTrue(prime.isProbablePrime(10));
            assertTrue(RSA.testMillerRabin(prime, 10));
            assertTrue(Prime19BitMin.compareTo(prime) <= 0);
            assertTrue(Prime19BitMax.compareTo(prime) >= 0);
        }
    }

    @Test void testGeneratePrimeLarge()
    {
        int primeBitLen = 1024;

        BigInteger min = BigInteger.ONE.shiftLeft(primeBitLen - 1);
        BigInteger max = min.shiftLeft(1).subtract(BigInteger.ONE);

        for (int idx = 0; idx < 2; idx++)
        {
            BigInteger largePrime = RSA.provablePrimeMaurer(primeBitLen);
            System.out.println("Prime #" + Integer.valueOf(idx));
            System.out.println(largePrime.toString(10));
            assertTrue(RSA.testMillerRabin(largePrime, 10)); 
            assertTrue(min.compareTo(largePrime) <= 0);
            assertTrue(max.compareTo(largePrime) >= 0);    
        }

    }

    @Test void testKeyGenerationEncryptDecrypt()
    {
        String secretText = "Look, ma a secret text!";

        for (int i = 1; i < 5; i++)
        {
            Pair<BigInteger, Pair<BigInteger, BigInteger>> privPub = RSA.generateKeyPair(1024);
            BigInteger d = privPub.first;
            BigInteger e = privPub.last.first;
            BigInteger m = privPub.last.last;
    
            byte[] ciphertext = RSA.encrypt(e, m, secretText.getBytes());
            byte[] cleartext = RSA.decrypt(d, m, ciphertext);
            System.out.println("Decrypted Text: " + new String(cleartext));
    
            byte secretNumber[] = { 42 };
            byte[] ciphertext_number = RSA.encrypt(e, m, secretNumber);
            byte[] cleartext_number = RSA.decrypt(d, m, ciphertext_number);
            assertTrue(Arrays.equals(secretNumber, cleartext_number));             
        }
    }

    @Test void testPaddingAndEncryption()
    {
        String clearText = "This shall test encryption of a padded clear text";
        for (int i = 1; i < 5; i++)
        {
            Pair<BigInteger, Pair<BigInteger, BigInteger>> privPub = RSA.generateKeyPair(1024);
            BigInteger d = privPub.first;
            BigInteger e = privPub.last.first;
            BigInteger m = privPub.last.last;
    
            byte ciphertext[] = RSA.padAndEncrypt(e, m, clearText.getBytes());
            byte unpaddedClearText[] = RSA.decryptAndUnpad(d, m, ciphertext);
            System.out.println(i);
            assertTrue(Arrays.equals(unpaddedClearText, clearText.getBytes()));            
        }
    }

}
