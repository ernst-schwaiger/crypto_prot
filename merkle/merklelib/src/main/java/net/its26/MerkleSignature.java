package net.its26;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class MerkleSignature 
{
    public static class MerkleTree 
    {
        private final List<KeyPair> keyPairs;
        private int numAvailable;
        public MerkleTree(int n)
        {
            int numAvailable = (2 << n);

            keyPairs = new ArrayList<>(numAvailable);

            try 
            {
                // Create a KeyPairGenerator for RSA
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
                
                // Initialize the key pair generator with a key size
                keyPairGen.initialize(2048); // You can adjust the size as needed

                for (int i = 0; i < numAvailable; i++)
                {
                    keyPairs.add(keyPairGen.generateKeyPair());
                }
                
            } 
            catch (NoSuchAlgorithmException e) 
            {
                System.out.println("Key pair generation failed: " + e.getMessage());
            }
        }
    }

    public static class LamportSignature
    {



    }
}
