package net.its26;

import java.security.SecureRandom;
import java.util.Arrays;

public class LamportSignature 
{
    private static final int NUM_BYTES_256_BIT_NUM = 32;
    public static final int NUM_BYTES_KEY = NUM_BYTES_256_BIT_NUM*2*256;
    public static final int NUM_BYTES_SIGNATURE = NUM_BYTES_256_BIT_NUM * 256;

    private static class Key
    {
        private final byte[] vals;

        public Key(byte[] vals)
        {
            assert(vals.length == NUM_BYTES_KEY);
            this.vals = vals;
        }

        public byte[] getBytes() { return vals; }

        protected byte[] sign(byte[] message) 
        {
            byte[] ret = new byte[NUM_BYTES_SIGNATURE];
            byte[] msgHash = Common.SHA_256_MD.digest(message);
            assert (msgHash.length == NUM_BYTES_256_BIT_NUM);
            for (int bitPos = 0; bitPos < 256; bitPos++)
            {
                int val = (msgHash[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // either 0 or 1
                int copyIdx = (NUM_BYTES_256_BIT_NUM * bitPos * 2) + val * NUM_BYTES_256_BIT_NUM;
                System.arraycopy(vals, copyIdx, ret, bitPos * NUM_BYTES_256_BIT_NUM, NUM_BYTES_256_BIT_NUM);
            }

            return ret;
        }

        protected boolean verifySignature(byte[] message, byte[] signature)
        {
            if (signature.length != NUM_BYTES_SIGNATURE)
            {
                return false;
            }

            byte[] hashSignature = sign(message);
            byte[] signHashes = new byte[NUM_BYTES_SIGNATURE];

            int start = 0;
            for (int bitPos = 0; bitPos < 256; bitPos++)
            {
                byte[] rangeToHash = Arrays.copyOfRange(signature, start, start + NUM_BYTES_256_BIT_NUM);
                byte[] hashOfRange = Common.SHA_256_MD.digest(rangeToHash);
                System.arraycopy(hashOfRange, 0, signHashes, bitPos * NUM_BYTES_256_BIT_NUM, NUM_BYTES_256_BIT_NUM);
                start += NUM_BYTES_256_BIT_NUM;
            }

            return Arrays.equals(hashSignature, signHashes);
        }
    }

    public static class PrivateKey extends Key
    {
        public PrivateKey(byte[] vals) { super(vals); }
        public byte[] sign(byte[] message) { return super.sign(message); }
    }

    public static class PublicKey extends Key
    {
        public PublicKey(byte[] vals) { super(vals); }

        public boolean verifySignature(byte[] message, byte[] signature)
        {
            return super.verifySignature(message, signature);
        }
    }

    public static class KeyPair
    {
        public final PrivateKey privateKey;
        public final PublicKey publicKey;

        public KeyPair(PrivateKey privateKey, PublicKey publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    public static KeyPair generateKeyPair()
    {
        SecureRandom secureRandom = new SecureRandom();

        // 256 val pairs, one val for false, one for true
        byte privKeyVals[] = new byte[NUM_BYTES_KEY];
        secureRandom.nextBytes(privKeyVals);
        // Same for the public key, the corresponding hashes
        byte pubKeyVals[] = new byte[NUM_BYTES_KEY];

        int start = 0;
        for (int i = 0; i < 256 * 2; i++)
        {
            byte[] rangeToHash = Arrays.copyOfRange(privKeyVals, start, start + NUM_BYTES_256_BIT_NUM);
            byte[] hashOfRange = Common.SHA_256_MD.digest(rangeToHash);
            System.arraycopy(hashOfRange, 0, pubKeyVals, start, hashOfRange.length);
            start += NUM_BYTES_256_BIT_NUM;
        }

        return new KeyPair(new PrivateKey(privKeyVals), new PublicKey(pubKeyVals));
    }
}
