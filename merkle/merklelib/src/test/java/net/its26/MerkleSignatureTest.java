package net.its26;
import org.junit.jupiter.api.Test;

import net.its26.MerkleSignature.MerkleTree;

import static org.junit.jupiter.api.Assertions.*;

public class MerkleSignatureTest 
{
    @Test void testMerkleSignatures()
    {
        
        // Build a Merkle Tree providing 2^n one-time Keys
        int n = 8;
        MerkleTree merkleTree = new MerkleTree(n);

        // Signing a message 2^n times must be successful
        String myMessageToSign = "Hollariediedoedeldie!";

        for (int i = 0; i < (1 << n); i++)
        {
            MerkleSignature.Signature signature = merkleTree.sign(myMessageToSign.getBytes());
            boolean result = MerkleTree.verifySignature(myMessageToSign.getBytes(), merkleTree.getPublicKey(), signature, n);
            assertTrue(result);
            System.out.println("Signing & verification using key #" + i + " was successful.");
        }

        // We are now out of keys
        MerkleSignature.Signature signatureShallBeNull = merkleTree.sign(myMessageToSign.getBytes());
        assertTrue(signatureShallBeNull == null);
    }    


}
