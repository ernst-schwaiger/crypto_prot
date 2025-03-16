package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.Optional;

public class ClientServerTest 
{
    @Test void testKeyModSerDeSer() 
    {

        BigInteger key = BigInteger.ONE.shiftLeft(32276);
        BigInteger modulus = BigInteger.valueOf(42);
        byte serialized[] = ClientServer.serializeKeyAndModulus(key, modulus);

        Optional<Pair<BigInteger, BigInteger>> optDeSerialized = ClientServer.deserializeKeyAndModulus(serialized);
        assertTrue(optDeSerialized.isPresent());
        BigInteger key2 = optDeSerialized.get().first;
        BigInteger modulus2 = optDeSerialized.get().last;

        assertEquals(key, key2);
        assertEquals(modulus, modulus2);
    }
}
