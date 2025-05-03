package net.its26;

import java.util.Arrays;

/**
 * Demonstrates a key recovery attack on Lamport signatures when the same key is used twice.
 */
public class KeyRecoveryAttack {

    private static final int NUM_BYTES_256_BIT_NUM = 32;

    public static void main(String[] args) {
        // Use SHA-256 as the hash function
        Common.IHashFunction hashFunction = Common.HASH_FUNC_SHA256;

        System.out.println("\n=== Key Recovery Attack on Lamport Signatures ===\n");


        // PART 1: Generate a key pair normally
        LamportSignature.KeyPair keyPair = LamportSignature.generateKeyPair(hashFunction);

        // PART 2: Use the key to sign two different messages (violating the one-time property)

        // First message reveals some bits of the private key
        byte[] message1 = "First transaction: Send $100 to Alice".getBytes();
        System.out.println("Message 1: " + new String(message1));
        byte[] signature1 = keyPair.privateKey.sign(message1);

        // Second message reveals additional bits of the private key
        byte[] message2 = "Second transaction: Send $500 to Bob".getBytes();
        System.out.println("Message 2: " + new String(message2));
        byte[] signature2 = keyPair.privateKey.sign(message2);

        // Verify both signatures are valid
        boolean validSig1 = keyPair.publicKey.verifySignature(message1, signature1);
        boolean validSig2 = keyPair.publicKey.verifySignature(message2, signature2);

        System.out.println("Signature 1 valid: " + validSig1);
        System.out.println("Signature 2 valid: " + validSig2);


        // PART 3: Attack begins - reconstruct private key from the two signatures

        // In Lamport signatures, when we sign a message:
        // - For each bit in the message hash that's 0, we reveal the "false" private key value
        // - For each bit in the message hash that's 1, we reveal the "true" private key value

        // Get message hashes to determine which parts of the private key were revealed
        byte[] messageHash1 = hashFunction.hash(message1);
        byte[] messageHash2 = hashFunction.hash(message2);

        // Create a reconstructed private key array (initially empty)
        byte[] reconstructedPrivateKey = new byte[LamportSignature.NUM_BYTES_KEY];

        // Track how many bits of the private key we've recovered
        int recoveredBits = 0;

        // Analyze the two signatures to extract private key bits
        for (int bitPos = 0; bitPos < 256; bitPos++) {
            int bit1 = (messageHash1[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // 0 or 1
            int bit2 = (messageHash2[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // 0 or 1

            // Extract the key parts from the signatures
            int sigOffset1 = bitPos * NUM_BYTES_256_BIT_NUM;
            int sigOffset2 = bitPos * NUM_BYTES_256_BIT_NUM;

            // Calculate offsets into the private key
            int falseKeyOffset = (NUM_BYTES_256_BIT_NUM * bitPos * 2);
            int trueKeyOffset = (NUM_BYTES_256_BIT_NUM * bitPos * 2) + NUM_BYTES_256_BIT_NUM;

            if (bit1 == 0 && bit2 == 1) {
                // We have both the "false" part (from sig1) and "true" part (from sig2)
                System.arraycopy(signature1, sigOffset1, reconstructedPrivateKey, falseKeyOffset, NUM_BYTES_256_BIT_NUM);
                System.arraycopy(signature2, sigOffset2, reconstructedPrivateKey, trueKeyOffset, NUM_BYTES_256_BIT_NUM);
                recoveredBits++;
            } else if (bit1 == 1 && bit2 == 0) {
                // We have both the "true" part (from sig1) and "false" part (from sig2)
                System.arraycopy(signature1, sigOffset1, reconstructedPrivateKey, trueKeyOffset, NUM_BYTES_256_BIT_NUM);
                System.arraycopy(signature2, sigOffset2, reconstructedPrivateKey, falseKeyOffset, NUM_BYTES_256_BIT_NUM);
                recoveredBits++;
            }
            // If both bits are the same, we only recover one part of this bit position
        }

        System.out.println("Fully recovered key bit positions: " + recoveredBits + " out of 256");
        System.out.println("On average, we expect to recover ~128 bit positions with two signatures.");
        System.out.println("This gives us partial knowledge of the private key.");


        // PART 4: Create a forged signature for a third message using the partial key
        System.out.println("\nTry forging a signature for a new message");

        // Create a message the victim never signed
        byte[] forgeryMessage = "FORGED: Transfer $9999 to Eve".getBytes();
        System.out.println("Forgery message: " + new String(forgeryMessage));

        // Hash of the message we want to forge
        byte[] forgeryHash = hashFunction.hash(forgeryMessage);

        // Create a forged signature
        byte[] forgedSignature = new byte[LamportSignature.NUM_BYTES_SIGNATURE];

        // For each bit position in the hash:
        for (int bitPos = 0; bitPos < 256; bitPos++) {
            int forgeryBit = (forgeryHash[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // 0 or 1
            int bit1 = (messageHash1[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // 0 or 1
            int bit2 = (messageHash2[bitPos / 8] & (1 << (bitPos % 8))) >> (bitPos % 8); // 0 or 1

            int sourceSignature;
            int sigOffset = bitPos * NUM_BYTES_256_BIT_NUM;
            int destOffset = bitPos * NUM_BYTES_256_BIT_NUM;

            if (forgeryBit == 0) {
                // We need the "false" private key value
                if (bit1 == 0) {
                    // Use signature1 for this bit
                    sourceSignature = 1;
                    System.arraycopy(signature1, sigOffset, forgedSignature, destOffset, NUM_BYTES_256_BIT_NUM);
                } else if (bit2 == 0) {
                    // Use signature2 for this bit
                    sourceSignature = 2;
                    System.arraycopy(signature2, sigOffset, forgedSignature, destOffset, NUM_BYTES_256_BIT_NUM);
                } else {
                    // We can't forge this bit - both signatures reveal the "true" value
                    sourceSignature = 0;
                }
            } else { // forgeryBit == 1
                // We need the "true" private key value
                if (bit1 == 1) {
                    // Use signature1 for this bit
                    sourceSignature = 1;
                    System.arraycopy(signature1, sigOffset, forgedSignature, destOffset, NUM_BYTES_256_BIT_NUM);
                } else if (bit2 == 1) {
                    // Use signature2 for this bit
                    sourceSignature = 2;
                    System.arraycopy(signature2, sigOffset, forgedSignature, destOffset, NUM_BYTES_256_BIT_NUM);
                } else {
                    // We can't forge this bit - both signatures reveal the "false" value
                    sourceSignature = 0;
                }
            }

            if (sourceSignature == 0) {
                System.out.println("Warning: Cannot forge bit position " + bitPos +
                        " - need " + (forgeryBit == 0 ? "false" : "true") +
                        " value but both signatures reveal the " +
                        (bit1 == 0 ? "false" : "true") + " value");
            }
        }

        // Verify if our forged signature works
        boolean forgerySuccessful = keyPair.publicKey.verifySignature(forgeryMessage, forgedSignature);

        System.out.println("\nForged signature verification: " + forgerySuccessful);

        if (!forgerySuccessful) {
            System.out.println("\nNote: Complete forgery might not be possible with just two signatures,");
            System.out.println("as we may not have recovered all needed private key components.");
            System.out.println("With more signatures using the same key, a complete forgery becomes more likely.");
        }


        // PART 5: Demonstrate with 4 different messages to increase success rate
        System.out.println("\n Try creating a more successful forgery with 4 messages");

        LamportSignature.KeyPair keyPair2 = LamportSignature.generateKeyPair(hashFunction);

        // Create 4 messages with bit patterns to maximize diversity
        byte[] specialMessage1 = new byte[32];
        byte[] specialMessage2 = new byte[32];
        byte[] specialMessage3 = new byte[32];
        byte[] specialMessage4 = new byte[32];

        Arrays.fill(specialMessage1, (byte) 0xAA); // 10101010
        Arrays.fill(specialMessage2, (byte) 0x55); // 01010101
        Arrays.fill(specialMessage3, (byte) 0xF0); // 11110000
        Arrays.fill(specialMessage4, (byte) 0x0F); // 00001111

        System.out.println("Using 4 specially crafted messages to maximize key bit recovery");

        // Sign all 4 messages
        byte[] sig1 = keyPair2.privateKey.sign(specialMessage1);
        byte[] sig2 = keyPair2.privateKey.sign(specialMessage2);
        byte[] sig3 = keyPair2.privateKey.sign(specialMessage3);
        byte[] sig4 = keyPair2.privateKey.sign(specialMessage4);

        // Hash all messages
        byte[] hash1 = hashFunction.hash(specialMessage1);
        byte[] hash2 = hashFunction.hash(specialMessage2);
        byte[] hash3 = hashFunction.hash(specialMessage3);
        byte[] hash4 = hashFunction.hash(specialMessage4);

        // Verify signatures
        System.out.println("Signature 1 valid: " + keyPair2.publicKey.verifySignature(specialMessage1, sig1));
        System.out.println("Signature 2 valid: " + keyPair2.publicKey.verifySignature(specialMessage2, sig2));
        System.out.println("Signature 3 valid: " + keyPair2.publicKey.verifySignature(specialMessage3, sig3));
        System.out.println("Signature 4 valid: " + keyPair2.publicKey.verifySignature(specialMessage4, sig4));

        // Attempt forgery using collected bits
        byte[] targetMessage = "SPECIAL FORGERY: Send money to attacker".getBytes();
        byte[] targetHash = hashFunction.hash(targetMessage);

        byte[] forgedSig = new byte[LamportSignature.NUM_BYTES_SIGNATURE];
        boolean fullForge = true;
        int bitsRecovered = 0;

        for (int bitPos = 0; bitPos < 256; bitPos++) {
            int bitIndex = bitPos / 8;
            int bitMask = 1 << (bitPos % 8);
            int desiredBit = (targetHash[bitIndex] & bitMask) != 0 ? 1 : 0;

            int sigOffset = bitPos * NUM_BYTES_256_BIT_NUM;

            boolean bitRecovered = false;

            // Check which message's hash has the matching bit and use its signature
            if (((hash1[bitIndex] & bitMask) != 0 ? 1 : 0) == desiredBit) {
                System.arraycopy(sig1, sigOffset, forgedSig, sigOffset, NUM_BYTES_256_BIT_NUM);
                bitRecovered = true;
            } else if (((hash2[bitIndex] & bitMask) != 0 ? 1 : 0) == desiredBit) {
                System.arraycopy(sig2, sigOffset, forgedSig, sigOffset, NUM_BYTES_256_BIT_NUM);
                bitRecovered = true;
            } else if (((hash3[bitIndex] & bitMask) != 0 ? 1 : 0) == desiredBit) {
                System.arraycopy(sig3, sigOffset, forgedSig, sigOffset, NUM_BYTES_256_BIT_NUM);
                bitRecovered = true;
            } else if (((hash4[bitIndex] & bitMask) != 0 ? 1 : 0) == desiredBit) {
                System.arraycopy(sig4, sigOffset, forgedSig, sigOffset, NUM_BYTES_256_BIT_NUM);
                bitRecovered = true;
            }

            if (!bitRecovered) {
                fullForge = false;
            } else {
                bitsRecovered++;
            }
        }

        System.out.println("\nRecovered key bits: " + bitsRecovered + "/256");
        System.out.println("Complete forgery possible: " + fullForge);

        boolean forgedValid = keyPair2.publicKey.verifySignature(targetMessage, forgedSig);
        System.out.println("Forged signature verification: " + forgedValid);
    }
}