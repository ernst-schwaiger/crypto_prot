package net.its26;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class MQV 
{
    private static final int SIZE_INT_BYTES = 4;

    public static final Optional<KeyPair> longTermKeyAlice = generateKeyPair(
        "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgyh65AZE2SscNSsK3INVoHSJ8jXlg9v6aLYG2oW2QlbGgCgYIKoZIzj0DAQehRANCAARDkiz0syKgKhc5Ob619xE0xQBFYO7RvxBiTvoBmaII/NwtkWgsOJMvRUPl58IKYqCBknlzu9RCfV08r1bsCMjl",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ5Is9LMioCoXOTm+tfcRNMUARWDu0b8QYk76AZmiCPzcLZFoLDiTL0VD5efCCmKggZJ5c7vUQn1dPK9W7AjI5Q=="
    );

    public static final Optional<KeyPair> longTermKeyBob = generateKeyPair(
        "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQguD8DEeK2O0i3iI4NkAmCbZfb99eBQVjpLqTvF0PjO7mgCgYIKoZIzj0DAQehRANCAASBQW3K6jL7Md28UCG/A4DKS/6hz9qq0ra24OV4HwjOFXevMRwNXl/kBzZE61XEJxkG6Cp5F5V9YkAsPwrF5w8E",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgUFtyuoy+zHdvFAhvwOAykv+oc/aqtK2tuDleB8IzhV3rzEcDV5f5Ac2ROtVxCcZBugqeReVfWJALD8KxecPBA=="
    );

    private static Optional<KeyPair> generateKeyPair(String privateKeyStr, String publicKeyStr)
    {
        KeyPair ret = null;
        try
        {
            byte[] decodedKey = Base64.getDecoder().decode(privateKeyStr);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            byte[] decodedPublicKey = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedPublicKey);
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);
            ret = new KeyPair(publicKey, privateKey);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException e)
        {

        }

        return Optional.ofNullable(ret);

    }

    static class Serializer
    {
        public byte serialized[];

        public Serializer()
        {
            this.serialized = new byte[0];
        }

        public Serializer ser1(int in)
        {
            byte tmp[] = new byte[serialized.length + 1];
            System.arraycopy(serialized, 0, tmp, 0, serialized.length);
            tmp[tmp.length - 1] = (byte)(in & 0xff);
            serialized = tmp;
            return this;
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

    static class Deserializer
    {
        private byte serialized[];

        public Deserializer(byte in[])
        {
            this.serialized = new byte[in.length];
            System.arraycopy(in, 0, serialized, 0, in.length);
        }
        
        public byte dser1()
        {
            assert(serialized.length >= 1);
            byte ret = serialized[0];
            serialized = Arrays.copyOfRange(serialized, 1, serialized.length);
            return ret;
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

    public static byte[] serializePubKey(ECPoint p)
    {
        byte x[] = p.getAffineX().toByteArray();
        byte y[] = p.getAffineY().toByteArray();
        Serializer s = new Serializer();
        s.ser4(x.length).ser4(y.length).serN(x).serN(y);
        return s.serialized;
    }

    public static ECPoint deserializePubKey(byte[] serialized)
    {
        Deserializer d = new Deserializer(serialized);
        int byteLenX = d.dser4();
        int byteLenY = d.dser4();

        byte XArr[] = d.dserN(byteLenX);
        byte YArr[] = d.dserN(byteLenY);

        BigInteger X = new BigInteger(XArr);
        BigInteger Y = new BigInteger(YArr);

        return new ECPoint(X, Y);
    }

    // Index "0" byte, followed by serialized public Key
    public static byte[] generateMQVSessionKeyMessage(ECPublicKey pubSessionKey)
    {
        Serializer s = new Serializer();
        s.ser1(0).serN(serializePubKey(pubSessionKey.getW()));
        return s.serialized;
    }

    public static Optional<ECPublicKey> parseMQVSessionKeyMessage(byte serialized[], ECParameterSpec ecSpec)
    {
        Optional<ECPublicKey> ret = Optional.empty();
        Deserializer d = new Deserializer(serialized);
        byte index = d.dser1();
        if (index == 0)
        {
            ECPoint p = deserializePubKey(d.serialized);
            ret = EC.generatePublicKey(p, ecSpec);
        }

        return ret;
    }

    public static byte[] receiveMessage(InputStream is) throws IOException
    {
        // Receive data dynamically
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        byte tempBuffer[] = new byte[4096]; // That's the longest byte stream we can process
        // int bytesRead = is.read(tempBuffer);
        // System.out.println("Read " + Integer.valueOf(bytesRead) + " bytes from Tcp.");
        // return tempBuffer;
        
        int bytesRead = 0;
        while ((bytesRead == 0) && (bytesRead = is.read(tempBuffer)) != -1) 
        {
            buffer.write(tempBuffer, 0, bytesRead); // Append to buffer
        }

        byte receivedMessage[] = buffer.toByteArray(); 
        return receivedMessage;
    }

    public static void sendMessage(byte payload[], OutputStream os) throws IOException
    {
        os.write(payload);
        os.flush();    
    }

    public static void printByteArray(byte[] array)
    {
        for (int i = 0; i < array.length; i++)
        {
            System.out.printf("%02X ", array[i]); // Print byte in hex, padded to 2 characters
            if ((i + 1) % 8 == 0) { // New line after every 8 bytes
                System.out.println();
            }
        }
        if (array.length % 8 != 0)
        {
            System.out.println();
        }
    }

}
