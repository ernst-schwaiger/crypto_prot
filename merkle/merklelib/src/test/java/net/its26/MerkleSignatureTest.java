package net.its26;
import org.junit.jupiter.api.Test;

import net.its26.MerkleSignature.MerkleTree;

import static org.junit.jupiter.api.Assertions.*;

public class MerkleSignatureTest 
{
    @Test void testSomething()
    {
        String myMessageToSign = "Hollariediedoedeldie!";
        MerkleTree merkleTree = new MerkleTree(2);
        assertTrue(merkleTree != null);

        byte[] signature = merkleTree.sign(myMessageToSign.getBytes());
        boolean result = merkleTree.verifySignature(myMessageToSign.getBytes(), signature);
        assertTrue(result);
    }    
}
