package net.its26;

import org.bouncycastle.util.Arrays;

import net.its26.Common.IHashFunction;

public class MerkleSignature 
{
    public static final int NUM_BYTES_SHA_256_HASH = 32;

    // Represents one node in the Merkle Hash Tree, 256bit/32byte
    public static class HashValue
    {
        private final byte[] hashValBytes;

        public HashValue(byte[] hashValBytes)
        {
            this.hashValBytes = hashValBytes;
        }

        // // Constructor for the leaves of the Merkle Tree: Hashes of the Lamport Public Keys.
        // public HashValue(LamportSignature.PublicKey publicKey)
        // {
        //     hashValBytes = Common.SHA_256_MD.digest(publicKey.getBytes());
        // }

        // // Constructor for the intermediate nodes and the root node of the Merkle Tree: Hash of the
        // // concatenation of the two child nodes.
        // public HashValue(HashValue firstChild, HashValue lastChild)
        // {
        //     Common.SHA_256_MD.update(firstChild.getBytes());
        //     hashValBytes = Common.SHA_256_MD.digest(lastChild.getBytes());
        // }

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
        private final boolean consumeKeys;
        private int numAvailableKeys;
        
        // Creates a Merkle tree supporting 2^n one-time keys
        public MerkleTree(int n, boolean consumeKeys, IHashFunction hashFunction)
        {
            assert((n > 1) && (n <= 8));
            this.consumeKeys = consumeKeys;

            numAvailableKeys = (1 << n);
            keyPairs = new LamportSignature.KeyPair[numAvailableKeys];
            
            hashValueTree = new HashValue[numAvailableKeys * 2 - 1];

            // Generate Private Key List and leaves of Merkle Tree
            for (int i = 0; i < numAvailableKeys; i++)
            {
                LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair(hashFunction);
                hashValueTree[i + numAvailableKeys - 1] = new HashValue(hashFunction.hash(keyPair.publicKey.getBytes()));
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
                    byte[] merged = Common.merge(hashValueTree[firstChildIdx].getBytes(), hashValueTree[firstChildIdx + 1].getBytes());
                    hashValueTree[j] = new HashValue(hashFunction.hash(merged)); 
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
            // ld(keyPairs.length) gives us the depth of the Merkle tree.
            int numLevels = (int)(Math.log(keyPairs.length) / Math.log(2.0));

            // prevent accidential re-use of a one-time key
            if (numAvailableKeys <= 0)
            {
                return null;
            }

            int keyIdx = keyPairs.length - numAvailableKeys;
            // sig' is the Lamport signature of the message using the private Key at pos keyIdx
            byte[] sig1 = keyPairs[keyIdx].privateKey.sign(message);

            // Y_i is the public Key at pos keyIdx
            byte[] Y_keyIdx = keyPairs[keyIdx].publicKey.getBytes();

            // The n+1 auth hashes are needed so the verifier can check the validity of the Lamport public key
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

            // Mark the current key pair as "consumed"
            if (consumeKeys)
            {
                --numAvailableKeys;
            }

            Signature sig = new Signature(keyIdx, sig1, Y_keyIdx, auth_hashes);

            return sig;
        }

        // message: message we check the validity of
        // publicKey: the root node of the merkle tree. Passed to the receiver as public key
        // signature: signature generated by the sender
        // n: Index of the public/private key pair. The receiver needs this to do the hashing of the auth hashes 
        // in the signature correctly
        public static boolean verifySignature(byte[] message, byte[] publicKey, Signature signature, int n, IHashFunction hashFunction)
        {
            // Verify that sig1 actually matches the signature of message using Y_keyIdx.
            LamportSignature.PublicKey lamportPublicKey = new LamportSignature.PublicKey(signature.Y_i, hashFunction);
            if (!lamportPublicKey.verifySignature(message, signature.sig1))
            {
                return false;
            }

            // Verify that the sent public key was a valid one
            byte[] hash = hashFunction.hash(signature.Y_i);

            // positionInfo appended as last byte to the signature
            int testKeyIdx = signature.keyIdx;

            // iteratively hash in all auth_n hashes. The resulting hash must equal the public key,
            // which is the root of the Merkle tree.
            for (int hashIdx = 0; hashIdx < signature.auth_hashes.length; hashIdx++)
            {
                byte[] auth_n = signature.auth_hashes[hashIdx];

                // testKeyIdx is the index of our current hash in the current level of the Merkle Tree
                // we use it to determine how to hash:
                boolean hash_auth_n_then_hash = ((testKeyIdx % 2) == 1);
                if (hash_auth_n_then_hash)
                {
                    hash = hashFunction.hash(Common.merge(auth_n, hash));
                }
                else
                {
                    hash = hashFunction.hash(Common.merge(hash, auth_n));
                }
                testKeyIdx = testKeyIdx / 2;
            }

            boolean ret = Arrays.areEqual(hash, publicKey);
            return ret;
        }
    }
}
