package net.its26;

import org.junit.jupiter.api.Test;

import net.its26.Common.DumbHash;
import net.its26.Common.IHashFunction;
import net.its26.MerkleSignature.MerkleTree;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

public class HashTest 
{
    @Test void testOneTimeSignature()
    {
        byte[] zero = new byte[0];
        // byte[] zero = new byte[1];
        // zero[0] = (byte) 0x00;
        byte[] h0;
        h0 = Common.HASH_FUNC_DUMB.hash(zero);
        System.out.println(bytesToBitString(h0));
        byte[] allOnes = new byte[32];
        Arrays.fill(allOnes, (byte) 0xFF);
        byte[] h1 = Common.HASH_FUNC_DUMB.hash(allOnes);
        System.out.println(bytesToBitString(h1));

        String myMessage = "Hollariediedoedeldie ist zweites Futur bei Sonnenaufgang.";
        byte[] hashwert = Common.HASH_FUNC_DUMB.hash(myMessage.getBytes());
        System.out.println(bytesToBitString(hashwert));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
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
    @Test void testMerkleSignature3()
    {
        // Alice builds Merkle Tree
        int n = 8;
        MerkleTree merkleTree = new MerkleTree(n, false, Common.HASH_FUNC_DUMB);
        
        
        // Alice signs with the same OTS 2 messages
        // For easier execution flow we constructed 2 messages. one has all 0 bits in the hash, the other one all 1 bits
        byte[] myMessageToSign0 = new byte[1];
        myMessageToSign0[0] = (byte) 0x00;
        byte[] myMessageToSign1 = new byte[256];
        Arrays.fill(myMessageToSign1, (byte) 0xff);
        MerkleSignature.Signature signature0 = merkleTree.sign(myMessageToSign0);
        MerkleSignature.Signature signature1 = merkleTree.sign(myMessageToSign1);
        // Alice sends 2 messages to Bob, Eve eavesdrops the two signed messages
        // and saves the private keys in two arrays 
        byte[] privateKeysZero = signature0.sig1;
        byte[] privateKeysOne = signature1.sig1;
        // merge the two arrays interleavingly and thereby reconstructs the private key
        byte[] privateKeyVals = shuffle(privateKeysZero, privateKeysOne);
        // Eve reconstruct a private key for the Lamport OTS
        LamportSignature.PrivateKey pk = new LamportSignature.PrivateKey(privateKeyVals, Common.HASH_FUNC_DUMB);
        
        // counterfeit message
        String message = "sehr wichtig";
        // signing of this message by Eve with Alices private key
        MerkleSignature.Signature signature = new MerkleSignature.Signature(signature0.keyIdx, pk.sign(message.getBytes()), signature0.Y_i, signature0.auth_hashes);
        // Bob verifies the counterfeit message and it was found to be authentic
        boolean ret = MerkleTree.verifySignature(message.getBytes(), merkleTree.getPublicKey(), signature, n, Common.HASH_FUNC_DUMB);
        assertTrue(ret);
        System.out.println(ret);
        
     
    } 


    
    // byte[] shuffle(byte[] zeros, byte[] ones) 
    // {
    //     byte[] ret = new byte[zeros.length + ones.length];
        
    //     for (int i = 0; i < zeros.length-20; i+=2)
    //     {
    //         System.out.println(i/2);
    //         System.arraycopy(zeros, i, ret, i*2, 32);
    //         System.arraycopy(ones, i, ret, i*2+1, 32);
    //     }
    //     System.out.println(ret.length/2);
    //     return ret;
    // }

    public static byte[] shuffle(byte[] a, byte[] b) {
        
        int BLOCK = 32;

        byte[] result = new byte[a.length + b.length];
        int blocksA = a.length / BLOCK;
        int blocksB = b.length / BLOCK;
        int max = Math.max(blocksA, blocksB);
    
        int dst = 0;                     // Schreib­position im Ergebnis
    
        for (int i = 0; i < max; i++) {
            if (i < blocksA) {           // 32‑Bytes‑Block aus a
                System.arraycopy(a, i * BLOCK, result, dst, BLOCK);
                dst += BLOCK;
            }
            if (i < blocksB) {           // 32‑Bytes‑Block aus b
                System.arraycopy(b, i * BLOCK, result, dst, BLOCK);
                dst += BLOCK;
            }
        }
        return result;
    }
    

    // LamportSignature.PublicKey genPublicKey(LamportSignature.PrivateKey pk, Common.IHashFunction hashFunction )
    // {
    //     byte[] pubKeyVals = new byte[pk.getBytes().length];
    //     int start = 0;
    //     for (int i = 0; i < 256 * 2; i++)
    //     {
    //         byte[] rangeToHash = Arrays.copyOfRange(pk.getBytes(), start, start + 32);
    //         byte[] hashOfRange = hashFunction.hash(rangeToHash);
    //         System.arraycopy(hashOfRange, 0, pubKeyVals, start, hashOfRange.length);
    //         start += 32;
    //     }
    //     return new LamportSignature.PublicKey(pubKeyVals, hashFunction);
    // }

}

