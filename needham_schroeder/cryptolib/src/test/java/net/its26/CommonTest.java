package net.its26;

import org.junit.jupiter.api.Test;

import net.its26.Common.SessionInfo;
import net.its26.Common.SessionResponseInfo;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.Optional;

import javax.crypto.SecretKey;

public class CommonTest 
{

    @Test
    void needhamSchroederTest()
    {
        // Alice creates a request for a session key to share with Bob and sends it to the server
        int nonceAlice = Common.generateNonce();
        byte[] sessionKeyRequest = Common.generateSessionKeyRequest(Common.ID_ALICE, Common.ID_BOB, nonceAlice);

        // The server parses the request, generates the session key and the response payload
        Optional<SessionInfo> optSessionInfo = Common.parseSessionKeyRequest(sessionKeyRequest);
        assertTrue(optSessionInfo.isPresent());
        assertEquals(Common.ID_ALICE, optSessionInfo.get().userLocal);
        assertEquals(Common.ID_BOB, optSessionInfo.get().userRemote);
        assertTrue(optSessionInfo.get().optNonce.isPresent());
        assertEquals(nonceAlice, optSessionInfo.get().optNonce.get());

        Optional<SecretKey> optSessionKey = Common.generateKey();
        assertTrue(optSessionKey.isPresent());
        byte[] sessionKeyData = optSessionKey.get().getEncoded();

        Optional<byte[]> optSessionKeyResponse = 
            Common.generateSessionKeyResponse(optSessionInfo.get().userLocal, 
                optSessionInfo.get().userRemote, 
                optSessionInfo.get().optNonce.get().intValue(), 
                sessionKeyData, 
                Common.AES_KEY_SERVER_ALICE, 
                Common.AES_KEY_SERVER_BOB);
        assertTrue(optSessionKeyResponse.isPresent());

        // Alice decrypts the response using the shared key with the server, parses the content
        // Verifies the correct nonce was sent back
        // and forwards the inner ciphertext to Bob
        Optional<SessionResponseInfo> optSessionResponseInfoAlice = 
            Common.parseSessionKeyResponse(optSessionKeyResponse.get(), Common.AES_KEY_SERVER_ALICE);
        assertTrue(optSessionResponseInfoAlice.isPresent());
        assertEquals(Common.ID_BOB, optSessionResponseInfoAlice.get().userRemote);
        assertTrue(optSessionResponseInfoAlice.get().optNonce.isPresent());
        assertEquals(nonceAlice, optSessionResponseInfoAlice.get().optNonce.get().intValue());
        assertTrue(optSessionResponseInfoAlice.get().optPayloadRemote.isPresent());

        System.out.println("Alice's Session Key:");
        Common.printByteArray(optSessionResponseInfoAlice.get().sessionKey);

        byte[] sessionRequest = Common.generateSessionRequest(optSessionResponseInfoAlice.get().optPayloadRemote.get());

        // Bob receives the request, decrypts it using the key shared with the server, and sends a nonce to Alice using
        // the obtained session key
        Optional<SessionResponseInfo> optSessionResponseInfoBob = 
            Common.parseSessionRequest(sessionRequest, Common.AES_KEY_SERVER_BOB);
        assertTrue(optSessionResponseInfoBob.isPresent());
        assertEquals(Common.ID_ALICE, optSessionResponseInfoBob.get().userRemote);
        System.out.println("Bob's Session Key:");
        Common.printByteArray(optSessionResponseInfoAlice.get().sessionKey);

        // Verify that Session keys of Alice and Bob are the same
        assertTrue(Arrays.equals(optSessionResponseInfoBob.get().sessionKey, optSessionResponseInfoAlice.get().sessionKey));

        byte[] sessionKey = optSessionResponseInfoBob.get().sessionKey;

        int nonceBob = Common.generateNonce();
        Optional<byte[]> optSessionResponse = Common.generateSessionResponse(nonceBob, sessionKey);
        assertTrue(optSessionResponse.isPresent());
        System.out.println("Bob sends encrypted nonce: " + nonceBob);

        // Alice receives the response from Bob, decrypts it using the session key, extract the nonce,
        // subtracts one and sends the encrypted, decremented nonce back to Bob
        Optional<Integer> optNonceFromBob = Common.parseSessionResponse(optSessionResponse.get(), sessionKey);
        assertTrue(optNonceFromBob.isPresent());
        int nonceBobMinusOne = optNonceFromBob.get().intValue() - 1;
        System.out.println("Alice sends back nonce, decremented by one: " + nonceBobMinusOne);
        Optional<byte[]> sessionResponseAck = Common.generateSessionResponseAck(nonceBobMinusOne, sessionKey);
        assertTrue(sessionResponseAck.isPresent());

        // Bob receives the message from Alice, decrypts it and verifies that the contained nonce is the original one
        // decremented by one
        Optional<Integer> optNonceFromAlice = Common.parseSessionResponseAck(sessionResponseAck.get(), sessionKey);
        assertTrue(optNonceFromAlice.isPresent());

        assertEquals(nonceBob - 1, optNonceFromAlice.get().intValue());
    }
}
