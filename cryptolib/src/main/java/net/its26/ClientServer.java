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
    private static final int SIZE_SHORT_BYTES = 2;


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

    public static byte[] serializeKeyAndModulus(BigInteger key, BigInteger modulus)
    {
        byte keyBytes[] = key.toByteArray();
        byte modulusBytes[] = modulus.toByteArray();

        byte[] ret = new byte[keyBytes.length + modulusBytes.length + 4];
        ret[0] = (byte)((keyBytes.length >> 8) & 0xff);
        ret[1] = (byte)(keyBytes.length & 0xff);
        ret[2] = (byte)((modulusBytes.length >> 8) & 0xff);
        ret[3] = (byte)(modulusBytes.length & 0xff);
        
        System.arraycopy(keyBytes, 0, ret, 4, keyBytes.length);
        System.arraycopy(modulusBytes, 0, ret, 4 + keyBytes.length, modulusBytes.length);

        return ret;
    }

    public static Optional<Pair<BigInteger, BigInteger>> deserializeKeyAndModulus(byte[] serialized)
    {
        Optional<Pair<BigInteger, BigInteger>> ret = Optional.empty();

        if (serialized.length > SIZE_SHORT_BYTES + SIZE_SHORT_BYTES)
        {
            int keyLenBytes = ((serialized[0] & 0xff) << 8) | (serialized[1] & 0xff);
            int modulusLenBytes = ((serialized[2] & 0xff) << 8) | (serialized[3] & 0xff);

            if (serialized.length == (keyLenBytes + modulusLenBytes + 4))
            {
                BigInteger key = new BigInteger(Arrays.copyOfRange(serialized, 4, 4 + keyLenBytes));
                BigInteger modulus = new BigInteger(Arrays.copyOfRange(serialized, 4 + keyLenBytes, 4 + keyLenBytes + modulusLenBytes));
                ret = Optional.of(new Pair<BigInteger, BigInteger>(key, modulus));
            }
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

    public static byte[] generateMsg01ClientServer(int random)
    {
        byte ret[] = new byte[1 + SIZE_INT_BYTES];
        ret[0] = 1;
        serialize(ret, random, 1);

        return ret;
    }

    public static Optional<Integer> parseMsg01ClientServer(byte payload[])
    {
        Optional<Integer> ret = Optional.empty();
        if ((payload.length == 5) && (payload[0] == 1))
        {
            int random = deserialize(payload, 1);
            ret = Optional.of(Integer.valueOf(random));
        }

        return ret;
    }

    public static Optional<byte[]> generateMsg02ServerClient(int random_c, int random_s, X509Certificate cert, PrivateKey privateKey)
    {
        Optional<byte[]> ret = Optional.empty();

        try
        {
            byte certBuf[] = cert.getEncoded();
            byte toSign[] = new byte[1 + SIZE_INT_BYTES + SIZE_INT_BYTES + SIZE_INT_BYTES + certBuf.length];
            toSign[0] = 2;
            serialize(toSign, random_s, 1);
            serialize(toSign, random_c, 1 + SIZE_INT_BYTES);
            serialize(toSign, certBuf.length, 1 + SIZE_INT_BYTES + SIZE_INT_BYTES);
            System.arraycopy(certBuf, 0, toSign, 1 + SIZE_INT_BYTES + SIZE_INT_BYTES + SIZE_INT_BYTES, certBuf.length);
            ret = appendSignature(toSign, privateKey);
        }
        catch (GeneralSecurityException e)
        {

        }

        return ret;
    }

    public static Optional<Pair<X509Certificate, Integer>> parseMsg02ServerClient(byte payload[], int random_c)
    {
        Optional<Pair<X509Certificate, Integer>> ret = Optional.empty();

        if ((payload.length >= 1 + SIZE_INT_BYTES * 2) && (payload[0] == 2))
        {
            int randomServer = deserialize(payload, 1);
            int randomClient = deserialize(payload, 1 + SIZE_INT_BYTES);
            int sizeCert =  deserialize(payload, 1 + 2 * SIZE_INT_BYTES);
            int signedPayloadLength = (1 + 3 * SIZE_INT_BYTES + sizeCert);

            if ((randomClient == random_c) && (payload.length >= signedPayloadLength))
            {
                byte signedPayload[] = Arrays.copyOfRange(payload, 0, signedPayloadLength);
                byte signature[] = Arrays.copyOfRange(payload, signedPayloadLength, payload.length);
                int certOffsetInPayload = 1 + 3 * SIZE_INT_BYTES;
                Optional<X509Certificate> optCert = createCertificate(Arrays.copyOfRange(payload, certOffsetInPayload, certOffsetInPayload + sizeCert));

                if (optCert.isPresent() && verifySignature(signedPayload, signature, optCert.get()))
                {
                    ret = Optional.of(new Pair<X509Certificate, Integer>(optCert.get(), Integer.valueOf(randomServer)));
                }
            }
        }

        return ret;
    }

    public static Optional<byte[]> generateMsg03ClientServer(int random_c, int random_s, X509Certificate cert, PrivateKey privateKey)
    {
        // Payload is exactly the same, just sending the client certificate, and using the clients private key for signing
        return generateMsg02ServerClient(random_c, random_s, cert, privateKey);
    }

    public static Optional<X509Certificate> parseMsg03ClientServer(byte payload[], int random_s, int random_c)
    {
        Optional<X509Certificate> ret = Optional.empty();

        if ((payload.length >= 1 + SIZE_INT_BYTES * 3) && (payload[0] == 3))
        {
            int randomServer = deserialize(payload, 1);
            int randomClient = deserialize(payload, 1 + SIZE_INT_BYTES);
            int sizeCert = deserialize(payload, 1 + SIZE_INT_BYTES + SIZE_INT_BYTES);
            int signedPayloadLength = (1 + 3 * SIZE_INT_BYTES + sizeCert);

            if ((random_s == randomServer) && (random_c == randomClient) && (sizeCert > 0) && 
                (payload.length >= signedPayloadLength))
            {
                byte signedPayload[] = Arrays.copyOfRange(payload, 0, signedPayloadLength);
                byte signature[] = Arrays.copyOfRange(payload, signedPayloadLength, payload.length - signedPayloadLength);
                
                Optional<X509Certificate> optCert = createCertificate(Arrays.copyOfRange(payload, 1 + 3 * SIZE_INT_BYTES, sizeCert));

                if (optCert.isPresent() && verifySignature(signedPayload, signature, optCert.get()))
                {
                    ret = optCert;
                }
            }
        }

        // Caller must verify that cert is valid and was signed with the root certificate
        return ret;
    }

    public static Optional<byte[]> generateMsg04ServerClient(Pair<BigInteger, BigInteger> pubKey, PrivateKey privateKey)
    {
        // FIXME: Continue here: Send our homemade public key and sign it using the private key of the certificate
        return Optional.empty();
    }


    private static boolean verifySignature(byte payloadToVerify[], byte signatureBytes[], X509Certificate cert)
    {
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

            byte payloadAndSignature[] = new byte[payloadToSign.length + signatureBytes.length];
            System.arraycopy(payloadToSign, 0, payloadAndSignature, 0, payloadToSign.length);
            System.arraycopy(signatureBytes, 0, payloadAndSignature, payloadToSign.length, signatureBytes.length);
            ret = Optional.of(payloadAndSignature);
        }
        catch (GeneralSecurityException e)
        {

        }

        return ret;

    }

    private static void serialize(byte buffer[], int val, int offset)
    {
        assert(buffer.length >= (offset + SIZE_INT_BYTES));
        buffer[offset] = (byte)((val >> 24) & 0xff);
        buffer[offset + 1] = (byte)((val >> 16) & 0xff);
        buffer[offset + 2] = (byte)((val >> 8) & 0xff);
        buffer[offset + 3] = (byte)(val & 0xff);
    }

    private static int deserialize(byte buffer[], int offset)
    {
        assert(buffer.length >= (offset + SIZE_INT_BYTES));
        int val = ((buffer[offset] & 0xff) << 24) | 
            ((buffer[offset + 1] & 0xff) << 16) | 
            ((buffer[offset + 2] & 0xff) << 8) |
            (buffer[offset + 3] & 0xff);
        return val;
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
