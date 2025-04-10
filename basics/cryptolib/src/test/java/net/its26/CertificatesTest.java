package net.its26;

import org.junit.jupiter.api.Test;

import net.its26.RSA.PrivatePublicKey;

import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Optional;

public class CertificatesTest
{

    @Test void testCertificateGeneration()
    {
        // Very important contract to sign
        final String CONTRACT_TO_SIGN = "I, the purchaser, hereby confirm that I'll buy this lollipop for the sum of 50 cents " +
                                        "(VAT included) and will deliver the money immediately after the reception of the lollipop.";

        // we are using our own, homegrown key pairs here, 1024 bit so the test is faster :-)
        PrivatePublicKey privPublicKeys = RSA.generateKeyPair(1024);
        // Convert our homegrown keys to a Key Pair we can build a certificate with
        Optional<KeyPair> optKeyPair = Certificates.generateKeyPair(privPublicKeys);

        assertTrue(optKeyPair.isPresent());

        Optional<X509Certificate> optCert = 
            Certificates.generateSelfSignedCert(optKeyPair.get(), "JohnDoeInc", "www.johndoe.com");

        // Ensure we have a certificate and that it has not expired
        assertTrue(optCert.isPresent());
        assertTrue(Certificates.isCertValid(optCert.get()));

        // Sign something, then verify the signature; this tests that our own private/public keys are working
        try
        {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(optKeyPair.get().getPrivate());
            signature.update(CONTRACT_TO_SIGN.getBytes());
            byte signatureBytes[] = signature.sign();

            signature.initVerify(optKeyPair.get().getPublic());
            signature.update(CONTRACT_TO_SIGN.getBytes());
            assertTrue(signature.verify(signatureBytes));            
        }
        catch (GeneralSecurityException e)
        {
            System.err.println(e.getMessage());
        }

    }

}
