package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;

public class CommonTest 
{
    @Test void squareAndMultiply() {

        BigInteger base = new BigInteger("34");
        BigInteger exponent = new BigInteger("12");

        BigInteger result = Common.squareAndMultiply(base, exponent);
        assertEquals(new BigInteger("2386420683693101056"), result);

    }

    @Test void squareAndMultiplyModulus()
    {
        BigInteger base = new BigInteger("34");
        BigInteger exponent = new BigInteger("12");
        BigInteger modulus = new BigInteger("43");
        BigInteger result = Common.squareAndMultiplyModulus(base, exponent, modulus);
        assertEquals(new BigInteger("16"), result);
    }
}
