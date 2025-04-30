package net.its26;

import org.bouncycastle.util.Arrays;

public class MerkleSignature 
{
    public static final int NUM_BYTES_SHA_256_HASH = 32;

    // Represents one node in the Merkle Hash Tree
    public static class HashValue
    {
        private final byte[] hashValBytes;

        public HashValue(LamportSignature.PublicKey publicKey)
        {
            hashValBytes = Common.SHA_256_MD.digest(publicKey.getBytes());
        }

        public HashValue(HashValue firstChild, HashValue lastChild)
        {
            Common.SHA_256_MD.update(firstChild.getBytes());
            hashValBytes = Common.SHA_256_MD.digest(lastChild.getBytes());
        }

        public byte[] getBytes() { return hashValBytes; }
    }

    // Contains the fields of a Merkle Signature
    public static class Signature
    {
        public final int keyIdx;            // index [0..2^n] of Key that was used for signing
        public final byte[] sig1;           // signature of message using private key <keyIdx> 
        public final byte[] Y_i;            // public key <keyIdx>
        public final byte[][] auth_hashes;  // auth hash values along the path in the Merkle Tree

        public Signature(int keyIdx, byte[] sig1, byte[] Y_i, byte[][] auth_hashes)
        {
            this.keyIdx = keyIdx;
            this.sig1 = sig1;
            this.Y_i = Y_i;
            this.auth_hashes = auth_hashes;
        }
    }    

    public static class MerkleTree 
    {
        private final LamportSignature.KeyPair[] keyPairs;
        private final HashValue[] hashValueTree;
        private int numAvailableKeys;
        
        public MerkleTree(int n)
        {
            assert((n > 1) && (n <= 8));
            numAvailableKeys = (1 << n);
            keyPairs = new LamportSignature.KeyPair[numAvailableKeys];
            
            hashValueTree = new HashValue[numAvailableKeys * 2 - 1];

            // Generate Private Key List and leaves of Merkle Tree
            for (int i = 0; i < numAvailableKeys; i++)
            {
                LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair();
                hashValueTree[i + numAvailableKeys - 1] = new HashValue(keyPair.publicKey);
                keyPairs[i] = keyPair;
            }

            // Generate intermediate nodes and top node of merkle tree from bottom up
            for (int level = n - 1; level >= 0; level--)
            {
                int startIdx = (1 << level) - 1;
                int startIdxChildren = startIdx + (1 << level);
                for (int j = startIdx; j < startIdxChildren; j++)
                {
                    int firstChildIdx = startIdxChildren + ((j - startIdx) * 2);
                    hashValueTree[j] = new HashValue(hashValueTree[firstChildIdx], hashValueTree[firstChildIdx + 1]); 
                }
            }
        }

        public int getNumAvailableKeys()
        {
            return numAvailableKeys;
        }

        public byte[] getPublicKey()
        {
            return hashValueTree[0].getBytes();
        }
        
        public Signature sign(byte[] message)
        {
            int numLevels = (int)(Math.log(keyPairs.length) / Math.log(2.0));

            if (numAvailableKeys <= 0)
            {
                return null;
            }

            int keyIdx = keyPairs.length - numAvailableKeys;
            // sig'
            byte[] sig1 = keyPairs[keyIdx].privateKey.sign(message);

            // Y_i
            byte[] Y_keyIdx = keyPairs[keyIdx].publicKey.getBytes();

            byte[][] auth_hashes = new byte[numLevels][NUM_BYTES_SHA_256_HASH];

            // get the auth_0, ..., auth_n hashes
            // Get the element in the Merkle Tree which corresponds to keyIdx
            int hashIdx = (hashValueTree.length - keyPairs.length) + keyIdx;

            int auth_hashes_idx = 0;
            while (hashIdx > 0)
            {
                // This is the index of auth_n in the merkle tree
                boolean siblingIsToTheLeft = ((hashIdx % 2) == 0);
                int siblingHashIdx = siblingIsToTheLeft ? hashIdx - 1 : hashIdx + 1;
                byte[] auth_n_bytes = hashValueTree[siblingHashIdx].getBytes();

                // auth_hashes
                System.arraycopy(auth_n_bytes, 0, auth_hashes[auth_hashes_idx], 0, auth_n_bytes.length);
                auth_hashes_idx++;

                // Continue with parent in the Merkle Tree
                hashIdx = (hashIdx - 1) / 2;
            }

            --numAvailableKeys;

            Signature sig = new Signature(keyIdx, sig1, Y_keyIdx, auth_hashes);

            return sig;
        }

        public static boolean verifySignature(byte[] message, byte[] publicKey, Signature signature, int n)
        {
            // Verify that sig1 actually matches the signature of message using Y_keyIdx.
            LamportSignature.PublicKey lamportPublicKey = new LamportSignature.PublicKey(signature.Y_i);
            if (!lamportPublicKey.verifySignature(message, signature.sig1))
            {
                return false;
            }

            // Verify that the sent public key was a valid one
            byte[] hash = Common.SHA_256_MD.digest(signature.Y_i);

            // positionInfo appended as last byte to the signature
            int testKeyIdx = signature.keyIdx;

            for (int hashIdx = 0; hashIdx < signature.auth_hashes.length; hashIdx++)
            {
                byte[] auth_n = signature.auth_hashes[hashIdx];

                // testKeyIdx is the index of our current hash in the current level of the Merkle Tree
                // we use it to determine how to hash:
                boolean hash_auth_n_then_hash = ((testKeyIdx % 2) == 1);
                if (hash_auth_n_then_hash)
                {
                    Common.SHA_256_MD.update(auth_n);
                    hash = Common.SHA_256_MD.digest(hash);
                }
                else
                {
                    Common.SHA_256_MD.update(hash);
                    hash = Common.SHA_256_MD.digest(auth_n);
                }
                testKeyIdx = testKeyIdx / 2;
            }

            boolean ret = Arrays.areEqual(hash, publicKey);
            return ret;
        }
    }
}
