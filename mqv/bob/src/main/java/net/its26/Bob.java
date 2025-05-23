/*
 * This source file was generated by the Gradle 'init' task
 */
package net.its26;

import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Optional;

public class Bob 
{
    private static final int LISTEN_PORT = 12345;

    public static void main(String[] args) 
    {
        try (ServerSocket serverSocket = new ServerSocket(LISTEN_PORT)) 
        {
            // Long term keys
            assert(MQV.longTermKeyBob.isPresent());
            assert(MQV.longTermKeyAlice.isPresent());
            KeyPair longTermKeys = MQV.longTermKeyBob.get();
            // We are only using Alice's public long term key here 
            ECPublicKey longTermPubKeyAlice = (ECPublicKey)MQV.longTermKeyAlice.get().getPublic();

            System.out.println("Listening on port " + LISTEN_PORT);

            while(true)
            {
                Socket socket = serverSocket.accept();
                System.out.println("Alice connected from: " + socket.getInetAddress());

                // Receive public session key from Alice
                byte[] rxPublicSessionKeyMessage = MQV.receiveMessage(socket.getInputStream());
                Optional<ECPublicKey> optSessionPubKeyAlice = MQV.parseMQVSessionKeyMessage(rxPublicSessionKeyMessage, longTermPubKeyAlice.getParams());
                assert(optSessionPubKeyAlice.isPresent());

                // Generate Bob's session key pair
                Optional<KeyPair> optSessionKeys = EC.generateKeyPair();
                assert(optSessionKeys.isPresent());
                KeyPair sessionKeys = optSessionKeys.get();

                // Send public session Key to Alice
                ECPublicKey sessionPubKeyBob = (ECPublicKey)sessionKeys.getPublic();
                byte[] txPublicSessionKeyMessage = MQV.generateMQVSessionKeyMessage(sessionPubKeyBob);
                MQV.sendMessage(txPublicSessionKeyMessage, socket.getOutputStream());

                // Calculate common secret, generate a hash out of it
                ECPoint secret = EC.generateSecret(sessionKeys, (ECPrivateKey)longTermKeys.getPrivate(), optSessionPubKeyAlice.get(), longTermPubKeyAlice);
                Optional<byte[]> optDigest = EC.getSHA256(secret);
                assert(optDigest.isPresent());
                System.out.println("Common hashed secret:");
                MQV.printByteArray(secret.getAffineY().toByteArray());
    
                socket.close();
            }
        }
        catch (Exception e) 
        {
            e.printStackTrace();
        }        
    }
}
