package net.its26;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class EC 
{
    static { Security.addProvider(new BouncyCastleProvider()); }

    public static KeyPair generateKeyPair() throws Exception 
    {
        // Get the EC curve parameters
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");

        // Create the KeyPairGenerator instance
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());

        // Generate the Key Pair
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }
}
