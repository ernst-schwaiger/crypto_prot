package net.its26;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
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

    public static boolean verifyCertificate(X509Certificate cert, X509Certificate trustedIssuerCert)
    {
        // As default, we reject the certificate
        boolean ret = false;
        PublicKey issuerPublicKey = trustedIssuerCert.getPublicKey();
        try
        {
            // FIXME: Verify identity of certificate and start/end dates!
            cert.verify(issuerPublicKey);
            // No exception, certificate has been signed with the issuers public key
            ret = true;
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

        if (serialized.length > 4)
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


}
