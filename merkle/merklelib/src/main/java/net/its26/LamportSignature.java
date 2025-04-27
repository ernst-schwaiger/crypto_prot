package net.its26;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class LamportSignature 
{
    public static final int NUM_BYTES_256_BIT_NUM = 32;
    private static final MessageDigest SHA_256_MD = get256MessageDigest();

    private static MessageDigest get256MessageDigest()
    {
        MessageDigest ret = null;
        try
        {
            ret = MessageDigest.getInstance("SHA-256");
        }
        catch(NoSuchAlgorithmException e)
        {
            System.err.println("Error: Could not retrieve SHA-256 message digest");
            System.exit(1);
        }

        return ret;
    }

    public final Key pubKey;
    public final Key privKey;

    public static class Key
    {
        private final byte[] vals;

        public Key(byte[] vals) throws NoSuchAlgorithmException
        {
            this.vals = vals;
        }

        public byte[] sign(byte[] message) 
        {
            byte[] ret = new byte[NUM_BYTES_256_BIT_NUM * 256];
            byte[] msgHash = SHA_256_MD.digest(message);
            assert (msgHash.length == NUM_BYTES_256_BIT_NUM);
            for (int bitPos = 0; bitPos < 256; bitPos++)
            {
                int val = (msgHash[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // either 0 or 1
                int copyIdx = (NUM_BYTES_256_BIT_NUM * bitPos * 2) + val * NUM_BYTES_256_BIT_NUM;
                System.arraycopy(vals, copyIdx, ret, bitPos * NUM_BYTES_256_BIT_NUM, NUM_BYTES_256_BIT_NUM);
            }

            return ret;
        }

        public boolean verifySignature(byte[] message, byte[] signature) throws NoSuchAlgorithmException
        {
            byte[] hashSignature = sign(message);
            byte[] signHashes = new byte[NUM_BYTES_256_BIT_NUM * 256];

            int start = 0;
            for (int bitPos = 0; bitPos < 256; bitPos++)
            {
                byte[] rangeToHash = Arrays.copyOfRange(signature, start, start + NUM_BYTES_256_BIT_NUM);
                byte[] hashOfRange = SHA_256_MD.digest(rangeToHash);
                System.arraycopy(hashOfRange, 0, signHashes, bitPos * NUM_BYTES_256_BIT_NUM, NUM_BYTES_256_BIT_NUM);
                start += NUM_BYTES_256_BIT_NUM;
            }

            return Arrays.equals(hashSignature, signHashes);
        }
    }


    public LamportSignature() throws NoSuchAlgorithmException
    {
        SecureRandom secureRandom = new SecureRandom();

        // 256 val pairs, one for false, one for true
        byte privKeyVals[] = new byte[NUM_BYTES_256_BIT_NUM*2*256];
        secureRandom.nextBytes(privKeyVals);
        // Same for the public key, the corresponding hashes
        byte pubKeyVals[] = new byte[NUM_BYTES_256_BIT_NUM*2*256];

        int start = 0;
        for (int i = 0; i < 256 * 2; i++)
        {
            byte[] rangeToHash = Arrays.copyOfRange(privKeyVals, start, start + NUM_BYTES_256_BIT_NUM);
            byte[] hashOfRange = SHA_256_MD.digest(rangeToHash);
            System.arraycopy(hashOfRange, 0, pubKeyVals, start, hashOfRange.length);
            start += NUM_BYTES_256_BIT_NUM;
        }

        privKey = new Key(privKeyVals);
        pubKey = new Key(pubKeyVals);
    }    
}
