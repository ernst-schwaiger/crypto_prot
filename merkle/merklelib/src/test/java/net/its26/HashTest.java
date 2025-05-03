package net.its26;

import org.junit.jupiter.api.Test;
import java.util.Arrays;

public class HashTest 
{
    @Test void testOneTimeSignature()
    {
        byte[] zero = new byte[1];
        zero[0] = (byte) 0x00;
        byte[] h0;
        h0 = Common.HASH_FUNC_DUMB.hash(zero);
        System.out.println(bytesToBitString(h0));

        byte[] allOnes = new byte[32];
        Arrays.fill(allOnes, (byte) 0xFF);
        byte[] h1 = Common.HASH_FUNC_DUMB.hash(allOnes);
        System.out.println(bytesToBitString(h1));

        String message = "TestTestTestTestTestTestTestTest";
        byte[] hashwert = Common.HASH_FUNC_DUMB.hash(message.getBytes());
        System.out.println(bytesToBitString(hashwert));
    }

    public static String bytesToBitString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 8);
        for (byte b : bytes) {
            for (int i = 7; i >= 0; i--) {
                sb.append(((b >> i) & 1) == 1 ? '1' : '0');
            }
        }
        return sb.toString();
    }
}

