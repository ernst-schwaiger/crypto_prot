package net.its26;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import javax.crypto.Cipher;

public class ClientServer 
{
    private static final int SIZE_INT_BYTES = 4;

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

    public static Optional<byte[]> encryptRSA(byte message[], PublicKey publicKey)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(message);
            ret = Optional.ofNullable(encryptedBytes);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println("Failed to encrypt, " + e.toString());
        }
        return ret;
    }

    public static Optional<byte[]> decryptRSA(byte ciphertext[], PrivateKey privateKey)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedBytes = cipher.doFinal(ciphertext);
            ret = Optional.ofNullable(decryptedBytes);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println("Failed to encrypt, " + e.toString());
        }

        return ret;
    }
    
    public static Optional<X509Certificate> createCertificate(String path)
    {
        X509Certificate cert = null;
        try (InputStream inStrm = new FileInputStream(path))
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate)cf.generateCertificate(inStrm);
        }
        catch(IOException | CertificateException e)
        {
            System.err.println("Could not open certificate file: " + e.toString());
        }

        return Optional.ofNullable(cert);
    }

    public static Optional<X509Certificate> createCertificate(byte buffer[])
    {
        X509Certificate cert = null;
        try
        {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream inputStream = new ByteArrayInputStream(buffer);
            cert = (X509Certificate)certFactory.generateCertificate(inputStream);
        }
        catch(CertificateException e)
        {
            System.err.println("Could not open certificate file: " + e.toString());
        }

        return Optional.ofNullable(cert);
    }

    public static Optional<PrivateKey> readPrivateKey(String keyFilePath)
    {
        Optional<PrivateKey> ret = Optional.empty();
        try 
        {
            String key = new String(Files.readAllBytes(Paths.get(keyFilePath)));
            // Remove header and footer of the PEM file
            key = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", ""); 
                    
            // Decode the base64 content
            byte[] decodedKey = Base64.getDecoder().decode(key);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            
            return ret = Optional.ofNullable(keyFactory.generatePrivate(keySpec));
        }
        catch(IOException | GeneralSecurityException e)
        {
            System.err.println("Could not open key file: " + e.toString());
        }

        return ret;
    }

    public static boolean verifyCertificate(X509Certificate cert, X509Certificate trustedIssuerCert, String commonName)
    {
        // As default, we reject the certificate
        boolean ret = false;
        PublicKey issuerPublicKey = trustedIssuerCert.getPublicKey();
        try
        {
            // Identity of certificate and start/end dates are checked by the
            // client and server applications
            cert.verify(issuerPublicKey);

            // Check common name field against expected one
            String principalString = cert.getSubjectX500Principal().getName();
            Optional<String> optCommonName = ClientServer.getFieldFromPrincipal(principalString, "CN");
            if (optCommonName.isPresent() && commonName.equals(optCommonName.get()))
            {
                // Verify that the certificate is valid at this point in time
                cert.checkValidity();
                ret = true;
            }
        }
        catch (GeneralSecurityException e)
        {
            System.err.println("Failed to verify certificate, " + e.toString());
        }

        return ret;
    }

    // Principal is a comma separated list of type <key>=<value>
    private static Optional<String> getFieldFromPrincipal(String principal, String keyName)
    {
        Optional<String> ret = Optional.empty();
        String fields[] = principal.split(",");
        for (String field : fields)
        {
            String keyVal[] = field.split("=");
            if ((keyVal.length == 2) && keyVal[0].equals(keyName))
            {
                ret = Optional.of(keyVal[1]);
                break;
            }
        }

        return ret;
    }

    public static int generateRandom()
    {
        BigInteger rnd = Common.getRandom(BigInteger.ZERO, BigInteger.ONE.shiftLeft(31).subtract(BigInteger.ONE));
        return rnd.intValue();
    }

    public static byte[] generateMsg01ClientServer(int random)
    {
        return new Serializer().ser1(1).ser4(random).serialized;
    }

    public static Optional<Integer> parseMsg01ClientServer(byte payload[])
    {
        Optional<Integer> ret = Optional.empty();
        if ((payload.length == 5) && (payload[0] == 1))
        {
            Deserializer d = new Deserializer(payload);
            d.dser1();
            int random = d.dser4();
            ret = Optional.of(Integer.valueOf(random));
        }

        return ret;
    }

    private static Optional<byte[]> generateMsg0203(int random_c, int random_s, X509Certificate cert, PrivateKey privateKey, int msgId)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Serializer s = new Serializer();
            byte certBuf[] = cert.getEncoded();
            s.ser1(msgId).ser4(random_s).ser4(random_c).ser4(certBuf.length).serN(certBuf);
            ret = appendSignature(s.serialized, privateKey);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    public static Optional<byte[]> generateMsg02ServerClient(int random_c, int random_s, X509Certificate cert, PrivateKey privateKey)
    {
        return generateMsg0203(random_c, random_s, cert, privateKey, 0x02);
    }

    public static Optional<byte[]> generateMsg03ClientServer(int random_c, int random_s, X509Certificate cert, PrivateKey privateKey)
    {
        return generateMsg0203(random_c, random_s, cert, privateKey, 0x03);
    }

    public static Optional<Pair<X509Certificate, Integer>> parseMsg02ServerClient(byte payload[], int random_c)
    {
        Optional<Pair<X509Certificate, Integer>> ret = Optional.empty();

        if ((payload.length >= 1 + SIZE_INT_BYTES * 2) && (payload[0] == 2))
        {
            Deserializer d = new Deserializer(payload);
            d.dser1();
            int randomServer = d.dser4();
            int randomClient = d.dser4();
            int sizeCert = d.dser4();
            int signedPayloadLength = (1 + 3 * SIZE_INT_BYTES + sizeCert);

            if ((randomClient == random_c) && (payload.length >= signedPayloadLength))
            {
                byte cert[] = d.dserN(sizeCert);
                Optional<X509Certificate> optCert = createCertificate(cert);
                if (optCert.isPresent() && verifySignature(payload, signedPayloadLength, optCert.get()))
                {
                    ret = Optional.of(new Pair<X509Certificate, Integer>(optCert.get(), Integer.valueOf(randomServer)));
                }
            }
        }

        return ret;
    }

    public static Optional<X509Certificate> parseMsg03ClientServer(byte payload[], int random_s, int random_c)
    {
        Optional<X509Certificate> ret = Optional.empty();

        if ((payload.length >= 1 + SIZE_INT_BYTES * 3) && (payload[0] == 3))
        {
            Deserializer d = new Deserializer(payload);
            d.dser1();
            int randomServer = d.dser4();
            int randomClient = d.dser4();
            int sizeCert = d.dser4();
            int signedPayloadLength = (1 + 3 * SIZE_INT_BYTES + sizeCert);

            if ((random_s == randomServer) && (random_c == randomClient) && (sizeCert > 0) && 
                 (payload.length >= signedPayloadLength))
            {
                byte cert[] = d.dserN(sizeCert);
                Optional<X509Certificate> optCert = createCertificate(cert);
                if (optCert.isPresent() && verifySignature(payload, signedPayloadLength, optCert.get()))
                {
                    ret = optCert;
                }            
            }
        }

        // Caller must verify that cert is valid and was signed with the root certificate
        return ret;
    }

    public static Optional<byte[]> generateMsg04ServerClient(int random_c, int random_s, Pair<BigInteger, BigInteger> pubKey, PrivateKey privateKey)
    {
        byte pubKeyBytes[] = pubKey.first.toByteArray();
        byte modulusBytes[] = pubKey.last.toByteArray();
        Serializer s = new Serializer();
        s.ser1(4).ser4(random_s).ser4(random_c).ser4(pubKeyBytes.length).ser4(modulusBytes.length).serN(pubKeyBytes).serN(modulusBytes);
        Optional<byte[]> ret = appendSignature(s.serialized, privateKey);
        return ret;
    }

    public static Optional<Pair<BigInteger, BigInteger>> parseMsg04ServerClient(byte payload[], int random_c, int random_s, X509Certificate cert)
    {
        Optional<Pair<BigInteger, BigInteger>> ret = Optional.empty();

        if ((payload.length >=  1 + SIZE_INT_BYTES * 4) && (payload[0] == 4))
        {
            Deserializer d = new Deserializer(payload);
            d.dser1(); // consume 1st byte, we checked that one above
            int randomServer = d.dser4();
            int randomClient = d.dser4();
            int sizePubKey = d.dser4();
            int sizeModulus = d.dser4();
            int signedPayloadLength = (1 + 4 * SIZE_INT_BYTES + sizePubKey + sizeModulus);
            
            if ((random_s == randomServer) && (random_c == randomClient) && (sizePubKey > 0) && (sizeModulus > 0) &&
                (payload.length >= signedPayloadLength))
            {
                byte pubKeyBytes[] = d.dserN(sizePubKey);
                byte modulusBytes[] = d.dserN(sizeModulus);
    
                if (verifySignature(payload, signedPayloadLength, cert))
                {
                    ret = Optional.of(new Pair<>(new BigInteger(1, pubKeyBytes), new BigInteger(1, modulusBytes)));
                }
            }
        }

        return ret;
    }

    public static Optional<byte[]> generateMsg05ClientServer(int random_c, int random_s, byte ciphertext[], PrivateKey privateKey)
    {
        Serializer s = new Serializer();
        s.ser1(5).ser4(random_s).ser4(random_c).ser4(ciphertext.length).serN(ciphertext);
        Optional<byte[]> ret = appendSignature(s.serialized, privateKey);
        return ret;
    }

    public static Optional<byte[]> parseMsg05ClientServer(byte payload[], int random_c, int random_s, X509Certificate cert)
    {
        Optional<byte[]> ret = Optional.empty();
        if ((payload.length >=  1 + SIZE_INT_BYTES * 3) && (payload[0] == 5))
        {
            Deserializer d = new Deserializer(payload);
            d.dser1(); // consume first byte
            int randomServer = d.dser4();
            int randomClient = d.dser4();
            int sizeCiphertext = d.dser4();
            int signedPayloadLength = 1 + SIZE_INT_BYTES * 3 + sizeCiphertext;

            if ((random_s == randomServer) && (random_c == randomClient) && (sizeCiphertext > 0) &&
                (payload.length >= signedPayloadLength))            
            {
                byte ciphertext[] = d.dserN(sizeCiphertext);
                if (verifySignature(payload, signedPayloadLength, cert))
                {
                    ret = Optional.of(ciphertext);
                }
            }
        }

        return ret;
    }

    private static boolean verifySignature(byte payloadAndSignature[], int signedPayloadLen, X509Certificate cert)
    {
        assert(payloadAndSignature.length > signedPayloadLen);
        Deserializer d = new Deserializer(payloadAndSignature);
        byte payloadToVerify[] = d.dserN(signedPayloadLen); // Payload to check against signature
        byte signatureBytes[] = d.dserN(d.size()); // Signature is the rest

        boolean ret = false;
        try
        {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(cert.getPublicKey());
            signature.update(payloadToVerify);
            ret = signature.verify(signatureBytes);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    private static Optional<byte[]> appendSignature(byte payloadToSign[], PrivateKey privateKey)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(payloadToSign);
            byte signatureBytes[] = signature.sign();
            ret = Optional.of(new Serializer().serN(payloadToSign).serN(signatureBytes).serialized);
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
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
            System.out.println("Read " + Integer.valueOf(bytesRead) + " bytes from Tcp");
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

}
