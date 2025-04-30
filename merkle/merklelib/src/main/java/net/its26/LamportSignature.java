package net.its26;

import java.security.SecureRandom;
import java.util.Arrays;

public class LamportSignature 
{
    // 256 bits are contained in 32 bytes
    private static final int NUM_BYTES_256_BIT_NUM = 32;
    // A Lamport private/public Key consists of two 256 element arrays of 256 bit hashes. The first array
    // represents the 'false' bit, the second array represents the 'true' bit.
    public static final int NUM_BYTES_KEY = NUM_BYTES_256_BIT_NUM*2*256;
    // A Lamport Signature is a sequence of 256 hashes each 256 bit long.
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
            // Get a 256 bit digest of the message to sign h(message)
            byte[] msgHash = Common.SHA_256_MD.digest(message);

            // For each bit of  h(message), either pick the "false" 256 bit hash, or the "true" 256 bit hash
            // The concatenated sequence of the 256 256-bit hashes is the Lamport signature
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

            // Repeat the signing process given the passed message (using the *public* key), which gives a sequence
            // of h(privateKey_idx), the hashSignature
            byte[] hashSignature = sign(message);
            byte[] signHashes = new byte[NUM_BYTES_SIGNATURE];

            int start = 0;
            // Go through each 256bit chunk of the signature (either the "false" or "true" bit sequence of the private key),
            // hash and concatenate. If the concatenated sequence and the hashSignature are equal, the signature was verified
            // successfully.
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

    // Private Key: Only the sign() method is public
    public static class PrivateKey extends Key
    {
        public PrivateKey(byte[] vals) { super(vals); }
        public byte[] sign(byte[] message) { return super.sign(message); }
    }

    // Public Key: Only the verifySignature() method is public
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

        // 256 val pairs, one val for false, one for true make up the one-time private key
        byte privKeyVals[] = new byte[NUM_BYTES_KEY];
        secureRandom.nextBytes(privKeyVals);
        // Same for the public key, the corresponding hashes of the private key values
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
