package net.its26;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import net.its26.RSA.PrivatePublicKey;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Date;
import java.util.Optional;


public class Certificates {
    
    public static Optional<X509Certificate> generateSelfSignedCert(KeyPair keyPair, String issuerName, String subjectName)
    {
        Optional<X509Certificate> ret = Optional.empty();

        try
        {
            // Validity range
            long now = System.currentTimeMillis();
            Date startDate = new Date(now);
            Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

            X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                    new X500Name("CN=" + issuerName),   // Issuer
                    BigInteger.valueOf(now),            // Serial number
                    startDate,                          // Start time
                    endDate,                            // End time
                    new X500Name("CN=" + subjectName),  // Subject
                    SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()) // Public key
            );

            // Step 3: Sign the certificate
            ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .getCertificate(certBuilder.build(signer));

            ret = Optional.of(certificate);
        }
        catch (Exception e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }    

    public static Optional<KeyPair> generateKeyPair(PrivatePublicKey privPublicKeys)
    {
        Optional<KeyPair> ret = Optional.empty();
        try
        {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(privPublicKeys.pubKey.n, privPublicKeys.pubKey.e));
            PrivateKey privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(privPublicKeys.pubKey.n, privPublicKeys.d));
   
            ret = Optional.of(new KeyPair(publicKey, privateKey));
    
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    public static boolean isCertValid(X509Certificate cert)
    {
        boolean ret = false;
        try
        {
            cert.checkValidity();
            ret = true;
        }
        catch(CertificateExpiredException | CertificateNotYetValidException e)
        {
            // we just eat the exception since we return false anyway if the cert is not valid
        }

        return ret;
    }
}
