package net.its26;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import net.its26.MerkleSignature.MerkleTree;

public class OTSReuse {
    
    @Test void testOTSReuse()
    {
        // Alice builds Merkle Tree
        int n = 8;
        MerkleTree merkleTree = new MerkleTree(n, false, Common.HASH_FUNC_DUMB);
        
        
        // Alice signs with the same OTS 2 messages
        // For easier execution flow we constructed 2 messages. one has all 0 bits in the hash, the other one all 1 bits
        byte[] messageToSign0 = new byte[1];
        messageToSign0[0] = (byte) 0x00;
        byte[] messageToSign1 = new byte[256];
        Arrays.fill(messageToSign1, (byte) 0xff);
        MerkleSignature.Signature signature0 = merkleTree.sign(messageToSign0);
        MerkleSignature.Signature signature1 = merkleTree.sign(messageToSign1);
        // Alice sends 2 messages to Bob, Eve eavesdrops the two signed messages
        // and saves the private keys in two arrays 
        byte[] privateKeysZero = signature0.sig1;
        byte[] privateKeysOne = signature1.sig1;
        // merge the two arrays interleavingly and thereby reconstructs the private key
        byte[] privateKeyVals = shuffle(privateKeysZero, privateKeysOne);
        // Eve reconstruct a private key for the Lamport OTS
        LamportSignature.PrivateKey pk = new LamportSignature.PrivateKey(privateKeyVals, Common.HASH_FUNC_DUMB);
        
        // counterfeit message
        String message = "sehr wichtig. Diese Nachricht wurde Alice signiert";
        // signing of this message by Eve with Alices private key
        MerkleSignature.Signature signature = new MerkleSignature.Signature(signature0.keyIdx, pk.sign(message.getBytes()), signature0.Y_i, signature0.auth_hashes);
        // Bob verifies the counterfeit message and it was found to be authentic
        boolean ret = MerkleTree.verifySignature(message.getBytes(), merkleTree.getPublicKey(), signature, n, Common.HASH_FUNC_DUMB);
        assertTrue(ret);
        System.out.println(ret);
        
    } 


    public static byte[] shuffle(byte[] a, byte[] b) {
        
        int BLOCK = 32;

        byte[] result = new byte[a.length + b.length];
        int blocksA = a.length / BLOCK;
        int blocksB = b.length / BLOCK;
        int max = Math.max(blocksA, blocksB);
    
        int dst = 0;                     
    
        for (int i = 0; i < max; i++) {
            if (i < blocksA) {           
                System.arraycopy(a, i * BLOCK, result, dst, BLOCK);
                dst += BLOCK;
            }
            if (i < blocksB) {           
                System.arraycopy(b, i * BLOCK, result, dst, BLOCK);
                dst += BLOCK;
            }
        }
        return result;
    }

}

