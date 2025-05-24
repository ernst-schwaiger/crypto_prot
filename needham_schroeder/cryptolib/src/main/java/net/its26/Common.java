package net.its26;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// Commonly used methods
public class Common 
{
    public static class SessionInfo
    {
        public final int userLocal;
        public final int userRemote;
        public final Optional<Integer> optNonce;

        public SessionInfo(int user1, int user2, Optional<Integer> optNonce)
        {
            this.userLocal = user1;
            this.userRemote = user2;
            this.optNonce = optNonce;
        }
    }

    public static class SessionResponseInfo
    {
        public final int userRemote;
        public final Optional<Integer> optNonce;
        public final byte[] sessionKey;
        public final Optional<byte[]> optPayloadRemote;

        public SessionResponseInfo(int userRemote, Optional<Integer> optNonce, byte[] sessionKey, Optional<byte[]> optPayloadRemote)
        {
            this.userRemote = userRemote;
            this.optNonce = optNonce;
            this.sessionKey = sessionKey;
            this.optPayloadRemote = optPayloadRemote;
        }
    }

    // Messages used in the Needham-Schroeder protocol
    public enum NHS
    {
        SESSION_KEY_REQUEST(1),
        SESSION_KEY_RESPONSE(2),
        SESSION_REQUEST(3),
        SESSION_RESPONSE(4),
        SESSION_FINISH(5);

        public final int id;

        private NHS(int id)
        {
            this.id = id;
        }
    }

    public static final int ID_ALICE = 0x01;
    public static final int ID_BOB = 0x02;

    public static final byte[] AES_KEY_SERVER_ALICE = 
    { 
        (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, 
        (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa, (byte)0xaa 
    };

    public static final byte[] AES_KEY_SERVER_BOB = 
    {
        (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, 
        (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb, (byte)0xbb 
    };    
   
    private static final int SIZE_INT_BYTES = 4;
    private static final int SIZE_AES_IV_BYTES = 16;
    private static final int SIZE_AES_KEY_BYTES = 128 / 8;

    public static final int SERVER_LISTEN_PORT = 4200;  
    public static final int BOB_LISTEN_PORT = 4202;
    public static final String SERVER_IP_ADDRESS= "localhost";
    public static final String BOB_IP_ADDRESS= "localhost";

    private static class Serializer
    {
        public byte serialized[];

        public Serializer()
        {
            this.serialized = new byte[0];
        }

        public Serializer ser4(int in)
        {
            byte tmp[] = new byte[serialized.length + SIZE_INT_BYTES];
            System.arraycopy(serialized, 0, tmp, 0, serialized.length);

            tmp[serialized.length] = (byte)((in >> 24) & 0xff);
            tmp[serialized.length + 1] = (byte)((in >> 16) & 0xff);
            tmp[serialized.length + 2] = (byte)((in >> 8) & 0xff);
            tmp[serialized.length + 3] = (byte)(in & 0xff);   
            serialized = tmp;
            return this;
        }

        public Serializer serN(byte in[])
        {
            byte tmp[] = new byte[serialized.length + in.length];
            System.arraycopy(serialized, 0, tmp, 0, serialized.length);
            System.arraycopy(in, 0, tmp, serialized.length, in.length);
            serialized = tmp;
            return this;
        }
    }

    private static class Deserializer
    {
        private byte serialized[];

        public Deserializer(byte in[])
        {
            this.serialized = new byte[in.length];
            System.arraycopy(in, 0, serialized, 0, in.length);
        }
        
        public int dser4()
        {
            assert(serialized.length >= SIZE_INT_BYTES);
            int ret = ((serialized[0] & 0xff) << 24) | 
                ((serialized[1] & 0xff) << 16) | 
                ((serialized[2] & 0xff) << 8) |
                (serialized[3] & 0xff);
            serialized = Arrays.copyOfRange(serialized, SIZE_INT_BYTES, serialized.length);
            return ret;
        }

        public byte[] dserN(int n)
        {
            assert(serialized.length >= n);
            byte ret[] = Arrays.copyOfRange(serialized, 0, n);
            serialized = Arrays.copyOfRange(serialized, n, serialized.length);
            return ret;            
        }
        
        public int size()
        {
            return serialized.length;
        }
    }

    public static Optional<SecretKey> generateKey()
    {
        Optional<SecretKey> ret = Optional.empty();

        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128); // AES key size
            ret = Optional.of(keyGen.generateKey());    
        }
        catch (NoSuchAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    private static SecretKey generateAES128BitKey(byte[] keyValue)
    {
        // we only support 128 bit keys
        assert(keyValue.length == (SIZE_AES_KEY_BYTES));
        return new SecretKeySpec(keyValue, "AES");
    }

    public static Optional<Pair<byte[], byte[]>> encrypt(byte plainText[], SecretKey key)
    {
        Optional<Pair<byte[], byte[]>> ret = Optional.empty();

        try
        {
            byte iv[] = new byte[SIZE_AES_IV_BYTES]; // 16 bytes for AES
            new SecureRandom().nextBytes(iv); // Secure random IV
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
            byte ciphertext[] = cipher.doFinal(plainText);

            ret = Optional.of(new Pair<>(iv, ciphertext));
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    public static Optional<byte[]> decrypt(byte cipherText[], byte iv[], SecretKey key)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            byte[] decryptedBytes = cipher.doFinal(cipherText);
            ret = Optional.of(decryptedBytes);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    public static Optional<byte[]> makeIVAndCiphertext(byte[] plainText, byte[] keyData)
    {
        Optional<byte[]> ret = Optional.empty();
        SecretKey key = generateAES128BitKey(keyData);

        Optional<Pair<byte[], byte[]>> optIVAndCipherText = encrypt(plainText, key);
        if (optIVAndCipherText.isPresent())
        {
            Serializer s = new Serializer();
            s.serN(optIVAndCipherText.get().first);
            s.serN(optIVAndCipherText.get().last);

            ret = Optional.of(s.serialized);
        }

        return ret;
    }

    public static Optional<byte[]> makeClearText(byte[] ivAndCipherText, byte[] keyData)
    {
        SecretKey key = generateAES128BitKey(keyData);
        Deserializer d = new Deserializer(ivAndCipherText);

        byte[] IV = d.dserN(SIZE_AES_IV_BYTES);
        byte[] cipherText = d.dserN(d.size());

        return decrypt(cipherText, IV, key);
    }

    public static void printByteArray(byte[] array)
    {
        for (int i = 0; i < array.length; i++)
        {
            System.out.printf("0x%02X ", array[i]); // Print byte in hex, padded to 2 characters
            if ((i + 1) % 16 == 0) { // New line after every 8 bytes
                System.out.println();
            }
        }
        if (array.length % 16 != 0)
        {
            System.out.println();
        }
    }

    public static byte[] receiveMessage(InputStream is) throws IOException
    {
        // Receive data dynamically
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        byte tempBuffer[] = new byte[4096]; // That's the longest byte stream we can process
        
        int bytesRead = 0;
        while ((bytesRead == 0) && (bytesRead = is.read(tempBuffer)) != -1) 
        {
            buffer.write(tempBuffer, 0, bytesRead); // Append to buffer
        }

        byte receivedMessage[] = buffer.toByteArray();

        System.out.println("Received:");
        printByteArray(receivedMessage);
        return receivedMessage;
    }

    public static void sendMessage(byte payload[], OutputStream os) throws IOException
    {
        os.write(payload);
        os.flush();

        System.out.println("Sent:");
        printByteArray(payload);
    }

    public static int getMessageId(byte[] data)
    {
        int ret = -1;
        Deserializer d = new Deserializer(data);

        if (d.size() >= SIZE_INT_BYTES)
        {
            ret = d.dser4();
        }

        return ret;
    }

    // Generates the SESSION_KEY_REQUEST message, sent from Alice to the Server
    public static byte[] generateSessionKeyRequest(int idLocal, int idRemote, int nonce)
    {
        Serializer s = new Serializer();
        s
            .ser4(NHS.SESSION_KEY_REQUEST.id)
            .ser4(idLocal)
            .ser4(idRemote)
            .ser4(nonce);
        return s.serialized;
    }

    // Parses the SESSION_KEY_REQUEST message, sent from Alice to the Server
    public static Optional<SessionInfo> parseSessionKeyRequest(byte[] data)
    {
        Optional<SessionInfo> ret = Optional.empty();
        
        if (data.length >= 12)
        {
            Deserializer d = new Deserializer(data);
            d.dser4(); // eat message id

            int user1 = d.dser4();
            int user2 = d.dser4();
            Optional<Integer> optNonce = Optional.empty();
            if (d.size() >= SIZE_INT_BYTES)
            {
                int nonce = d.dser4();
                optNonce = Optional.of(Integer.valueOf(nonce));
            }

            ret = Optional.of(new SessionInfo(user1, user2, optNonce));
        }

        return ret;
    }

    // Generates the SESSION_KEY_RESPONSE message, sent from the Server back to Alice
    public static Optional<byte[]> generateSessionKeyResponse(int idLocal, int idRemote, int nonce, byte[] sessionKey, byte[] keyLocalServer, byte[] keyRemoteServer)
    {
        assert(sessionKey.length == SIZE_AES_KEY_BYTES);
        assert(keyRemoteServer.length == SIZE_AES_KEY_BYTES);
        assert(keyLocalServer.length == SIZE_AES_KEY_BYTES);

        Optional<byte[]> ret = Optional.empty();

        SecretKey aesKeyLocalServer = generateAES128BitKey(keyLocalServer);

        Optional<byte[]> optEncryptedSessionRequest = generateEncryptedSessionRequest(idLocal, sessionKey, keyRemoteServer);

        if (optEncryptedSessionRequest.isPresent())
        {
            Serializer sPlain = new Serializer();

            sPlain
                .ser4(nonce)
                .serN(sessionKey)
                .ser4(idRemote)
                .serN(optEncryptedSessionRequest.get());

            Optional<Pair<byte[], byte[]>> optIVAndCiphertextAll = encrypt(sPlain.serialized, aesKeyLocalServer);

            if (optIVAndCiphertextAll.isPresent())
            {
                Serializer sCipher = new Serializer();

                sCipher
                    .ser4(NHS.SESSION_KEY_RESPONSE.id)
                    .serN(optIVAndCiphertextAll.get().first)
                    .serN(optIVAndCiphertextAll.get().last);

                ret = Optional.of(sCipher.serialized);
            }
        }

        return ret;
    }

    public static Optional<byte[]> generateEncryptedSessionRequest(int idLocal, byte[] sessionKey, byte[] keyRemoteServer)
    {
        Optional<byte[]> ret = Optional.empty();
        SecretKey aesKeyRemoteServer = generateAES128BitKey(keyRemoteServer);
        Serializer sRemote = new Serializer();
        sRemote
            .serN(sessionKey)
            .ser4(idLocal);
        Optional<Pair<byte[], byte[]>> optIVAndCiphertextRemote = encrypt(sRemote.serialized, aesKeyRemoteServer);    
        
        if (optIVAndCiphertextRemote.isPresent())
        {
            Serializer encrypted = new Serializer();
            encrypted
                .serN(optIVAndCiphertextRemote.get().first)
                .serN(optIVAndCiphertextRemote.get().last);

            ret = Optional.of(encrypted.serialized);
        }

        return ret;
    }

    // Parses the SESSION_KEY_RESPONSE message, sent from the Server back to Alice
    public static Optional<SessionResponseInfo> parseSessionKeyResponse(byte[] data, byte[] keyLocalServer)
    {
        // will contain the session key and the Id of the local node, encrypted with the key shared by the server and the remote node
        Optional<SessionResponseInfo> ret = Optional.empty();
        
        if (data.length > SIZE_INT_BYTES + SIZE_AES_IV_BYTES)
        {
            Deserializer d = new Deserializer(data);
            d.dser4();  // eat the message id, should have been checked by caller already
            byte[] IV1 = d.dserN(SIZE_AES_IV_BYTES);
            byte[] cipher1 = d.dserN(d.size());

            SecretKey keyLocal = generateAES128BitKey(keyLocalServer);
            Optional<byte[]> clearText1 = decrypt(cipher1, IV1, keyLocal);

            if (clearText1.isPresent() && clearText1.get().length > SIZE_INT_BYTES + SIZE_AES_KEY_BYTES + SIZE_INT_BYTES)
            {
                Deserializer d2 = new Deserializer(clearText1.get());
                int nonce = d2.dser4();
                byte[] sessionKeyData = d2.dserN(SIZE_AES_KEY_BYTES);
                int userRemote = d2.dser4();
                Optional<byte[]> optPayloadRemote = Optional.of(d2.dserN(d2.size()));

                ret = Optional.of(new SessionResponseInfo(userRemote, Optional.of(Integer.valueOf(nonce)), sessionKeyData, optPayloadRemote));
            }
        }

        return ret;
    }

    // Generates the SESSION_REQUEST message, sent from Alice to Bob
    public static byte[] generateSessionRequest(byte[] encryptedDataForRemote)
    {
        Serializer s = new Serializer();
        return s.ser4(NHS.SESSION_REQUEST.id).serN(encryptedDataForRemote).serialized;
    }

    // Parses the SESSION_REQUEST message, sent from Alice to Bob
    public static Optional<SessionResponseInfo> parseSessionRequest(byte[] request, byte[] keyLocalServer)
    {
        Optional<SessionResponseInfo> ret = Optional.empty();
        Deserializer d = new Deserializer(request);

        if (d.size() > SIZE_AES_IV_BYTES + SIZE_INT_BYTES)
        {
            d.dser4(); // eat message id. Already checked by caller
            SecretKey key = generateAES128BitKey(keyLocalServer);

            byte[] IV = d.dserN(SIZE_AES_IV_BYTES);
            byte[] cipherText = d.dserN(d.size());
            Optional<byte[]> optClearText = decrypt(cipherText, IV, key);

            if (optClearText.isPresent() && optClearText.get().length > SIZE_INT_BYTES)
            {
                Deserializer d2 = new Deserializer(optClearText.get());
                byte[] sessionKey = d2.dserN(d2.size() - SIZE_INT_BYTES);
                int remoteId = d2.dser4();
                ret = Optional.of(new SessionResponseInfo(remoteId, Optional.empty(), sessionKey, Optional.empty()));
            }
        }

        return ret;
    }

    private static Optional<byte[]> generateEncryptedNonceWithMsgId(int msgId, int nonce, byte[] sessionKey)
    {
        Optional<byte[]> ret = Optional.empty();
        Serializer s = new Serializer();
        s.ser4(nonce);
        SecretKey key = Common.generateAES128BitKey(sessionKey);
        Optional<Pair<byte[], byte[]>> optIVAndCiphertext = Common.encrypt(s.serialized, key);

        if (optIVAndCiphertext.isPresent())
        {
            Serializer s2 = new Serializer();
            s2.ser4(msgId).serN(optIVAndCiphertext.get().first).serN(optIVAndCiphertext.get().last);
            ret = Optional.of(s2.serialized);
        }

        return ret;        
    }

    // Generates the SESSION_RESPONSE message, sent from Bob to Alice
    public static Optional<byte[]> generateSessionResponse(int nonce, byte[] sessionKey)
    {
        return generateEncryptedNonceWithMsgId(NHS.SESSION_RESPONSE.id, nonce, sessionKey);
    }

    // Parses the SESSION_RESPONSE message, sent from Bob to Alice
    public static Optional<Integer> parseSessionResponse(byte[] request, byte[] sessionKey)
    {
        Optional<Integer> ret = Optional.empty();
        Deserializer d = new Deserializer(request);

        if (d.size() > SIZE_INT_BYTES + SIZE_AES_IV_BYTES)
        {
            d.dser4(); // eat message id
            byte[] IV = d.dserN(SIZE_AES_IV_BYTES);
            byte[] cipherText = d.dserN(d.size());
            SecretKey key = Common.generateAES128BitKey(sessionKey);

            Optional<byte[]> optClearText = Common.decrypt(cipherText, IV, key);
            if (optClearText.isPresent() && optClearText.get().length == SIZE_INT_BYTES)
            {
                Deserializer d2 = new Deserializer(optClearText.get());
                ret = Optional.of(Integer.valueOf(d2.dser4()));
            }
        }

        return ret;  
    }

    // Generates the SESSION_FINISH message, sent from Alice to Bob
    public static Optional<byte[]> generateSessionResponseAck(int nonce, byte[] sessionKey)
    {
        return generateEncryptedNonceWithMsgId(NHS.SESSION_FINISH.id, nonce, sessionKey);
    }

    // Parses the SESSION_FINISH message, sent from Alice to Bob
    public static Optional<Integer> parseSessionResponseAck(byte[] request, byte[] sessionKey)
    {
        return parseSessionResponse(request, sessionKey);
    }

    public static int generateNonce()
    {
        SecureRandom secureRandom = new SecureRandom();
        return secureRandom.nextInt();
    }
}
