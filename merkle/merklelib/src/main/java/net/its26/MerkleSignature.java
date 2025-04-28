package net.its26;

import org.bouncycastle.util.Arrays;

public class MerkleSignature 
{
    public static final int NUM_BYTES_SHA_256_HASH = 32;

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

        public byte[] sign(byte[] message)
        {
            int numLevels = (int)(Math.log(keyPairs.length) / Math.log(2.0));

            // contains sig', Y_i, and auth_0, ... auth_numLevels-1
            byte[] ret = new byte[getMerkleSignatureByteLength(numLevels)];

            if (numAvailableKeys <= 0)
            {
                return null;
            }

            int tgtCopyIdx = 0;
            int keyIdx = keyPairs.length - numAvailableKeys;
            // sig'
            byte[] sig1 = keyPairs[keyIdx].privateKey.sign(message);
            System.arraycopy(sig1, 0, ret, tgtCopyIdx, sig1.length);
            tgtCopyIdx += sig1.length;

            // Y_i
            byte[] Y_keyIdx = keyPairs[keyIdx].publicKey.getBytes();
            System.arraycopy(Y_keyIdx, 0, ret, tgtCopyIdx, Y_keyIdx.length);
            tgtCopyIdx += Y_keyIdx.length;

            // get the auth_0, ..., auth_n hashes
            // Get the element in the Merkle Tree which corresponds to keyIdx
            int hashIdx = (hashValueTree.length - keyPairs.length) + keyIdx;
            int positionInfo = 0;
            int positionInfoIdx = 0;
            while (hashIdx > 0)
            {
                // This is the index of auth_n in the merkle tree
                boolean siblingIsToTheLeft = ((hashIdx % 2) == 0);
                int siblingHashIdx = siblingIsToTheLeft ? hashIdx - 1 : hashIdx + 1;
                if (siblingIsToTheLeft)
                {
                    positionInfo = positionInfo + (1 << positionInfoIdx);
                }
                byte[] auth_n_bytes = hashValueTree[siblingHashIdx].getBytes();
                System.arraycopy(auth_n_bytes, 0, ret, tgtCopyIdx, auth_n_bytes.length);
                tgtCopyIdx += auth_n_bytes.length;

                // Continue with parent in the Merkle Tree
                hashIdx = (hashIdx - 1) / 2;
                positionInfoIdx++;
            }

            // Append the position info as last byte
            assert((positionInfo >= 0) && (positionInfo <= 255));
            ret[ret.length - 1] = (byte)positionInfo;

            --numAvailableKeys;

            return ret;
        }

        private static int getMerkleSignatureByteLength(int numLevels)
        {
            // contains sig', Y_i, and auth_0, ... auth_numLevels-1, and the position info bits as last byte
            return LamportSignature.NUM_BYTES_SIGNATURE + LamportSignature.NUM_BYTES_KEY + numLevels * NUM_BYTES_SHA_256_HASH + 1;
        }

        public static boolean verifySignature(byte[] message, byte[] publicKey, byte[] signature, int n)
        {
            // check for proper merkle signature length
            if (signature.length != getMerkleSignatureByteLength(n))
            {
                return false;
            }

            // Verify that sig1 actually matches the signature of message using Y_keyIdx.
            byte[] sig1 = Arrays.copyOfRange(signature, 0, LamportSignature.NUM_BYTES_SIGNATURE);
            byte[] Y_keyIdx = Arrays.copyOfRange(signature, LamportSignature.NUM_BYTES_SIGNATURE, LamportSignature.NUM_BYTES_SIGNATURE + LamportSignature.NUM_BYTES_KEY);
            LamportSignature.PublicKey lamportPublicKey = new LamportSignature.PublicKey(Y_keyIdx);
            if (!lamportPublicKey.verifySignature(message, sig1))
            {
                return false;
            }

            // Verify that the sent public key was a valid one
            byte[] hash = Common.SHA_256_MD.digest(Y_keyIdx);
            int hashIdx = LamportSignature.NUM_BYTES_SIGNATURE + LamportSignature.NUM_BYTES_KEY;

            // positionInfo appended as last byte to the signature
            int positionInfo = signature[signature.length - 1];
            int positionInfoIdx = 0;
            while (hashIdx < (signature.length - 1))
            {
                byte[] auth_n = Arrays.copyOfRange(signature, hashIdx, hashIdx + NUM_BYTES_SHA_256_HASH);

                // The position info tells us how to hash: h(hash||authinfo_n) or h(authinfo_n||hash)
                if ((positionInfo & (1 << positionInfoIdx)) > 0)
                {
                    Common.SHA_256_MD.update(auth_n);
                    hash = Common.SHA_256_MD.digest(hash);
                }
                else
                {
                    Common.SHA_256_MD.update(hash);
                    hash = Common.SHA_256_MD.digest(auth_n);
                }

                hashIdx += NUM_BYTES_SHA_256_HASH;

                positionInfoIdx++;
            }

            return Arrays.areEqual(hash, publicKey);
        }
    }
}
