package net.its26;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

public class EC 
{
    private static final org.bouncycastle.jce.spec.ECParameterSpec EC_SPEC;

    // This class only supports the prime256v1 curve 
    static
    {
        Security.addProvider(new BouncyCastleProvider()); 
        EC_SPEC = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("prime256v1");
    }

    public static Optional<KeyPair> generateKeyPair()
    {
        KeyPair ret = null;

        try
        {
            // Create the KeyPairGenerator instance
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECMQV", "BC");
            keyPairGenerator.initialize(EC_SPEC, new SecureRandom());
            ret = keyPairGenerator.generateKeyPair();

        }
        catch(Exception e)
        {

        }

        return Optional.ofNullable(ret);
    }

    // sessionKey ephemeral local session key pair
    // a long term private key
    // Y public part of remote ephemeral session key pair
    // B public part of remote long term key pair
    public static ECPoint generateSecret(KeyPair sessionKey, ECPrivateKey a, ECPublicKey Y, ECPublicKey B)
    {
        int h = getCofactor();
        BigInteger YInverse = generateInverse(Y);
        BigInteger S = generateS(sessionKey, a);

        ECPoint p1 = scalarMultiply(B.getW(), YInverse);
        ECPoint p2 = pointAdd(Y.getW(), p1);
        ECPoint K = scalarMultiply(p2, S.multiply(BigInteger.valueOf(h)));

        return K;
    }

    // This gives us a 256bit symmetric Key
    public static Optional<byte[]> getSHA256(ECPoint p)
    {
        Optional<byte[]> ret = Optional.empty();
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(p.getAffineX().toByteArray());
            digest.update(p.getAffineY().toByteArray());
            ret = Optional.of(digest.digest());
        }
        catch(NoSuchAlgorithmException e)
        {
            System.err.println(e.getMessage());
        }

        return ret;
    }

    private static BigInteger generateS(KeyPair sessionKey, ECPrivateKey a)
    {
        ECPrivateKey x = (ECPrivateKey) sessionKey.getPrivate();
        ECPublicKey X = (ECPublicKey) sessionKey.getPublic();
        BigInteger XInverse = generateInverse(X);
        BigInteger n = getOrder();

        // S = (x + XInv*a) mod n
        BigInteger S = x.getS().add(XInverse.multiply(a.getS())).mod(n);
        return S;
    }

    public static Optional<ECPublicKey> generatePublicKey(ECPoint p, ECParameterSpec ecSpec)
    {
        ECPublicKey ret = null;

        try
        {         
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(p, ecSpec);
            ret = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException e)
        {
            System.err.println(e.getMessage());
        }

        return Optional.ofNullable(ret);
    }

    private static ECPoint scalarMultiply(ECPoint p, BigInteger scalar)
    {
        org.bouncycastle.math.ec.ECPoint bcPoint =
            EC_SPEC.getCurve().createPoint(p.getAffineX(), p.getAffineY());

        org.bouncycastle.math.ec.ECPoint result = bcPoint.multiply(scalar).normalize();

        BigInteger resX = result.getAffineXCoord().toBigInteger();
        BigInteger resY = result.getAffineYCoord().toBigInteger();
        return new ECPoint(resX, resY);
    }

    private static ECPoint pointAdd(ECPoint p, ECPoint q)
    {
        org.bouncycastle.math.ec.ECPoint bcPointP =
            EC_SPEC.getCurve().createPoint(p.getAffineX(), p.getAffineY());
        org.bouncycastle.math.ec.ECPoint bcPointQ =
            EC_SPEC.getCurve().createPoint(q.getAffineX(), q.getAffineY());

        org.bouncycastle.math.ec.ECPoint result = bcPointP.add(bcPointQ).normalize();
        BigInteger resX = result.getAffineXCoord().toBigInteger();
        BigInteger resY = result.getAffineYCoord().toBigInteger();
        return new ECPoint(resX, resY);
    }

    private static BigInteger generateInverse(ECPublicKey R)
    {
        ECPoint ecPoint = R.getW();
        BigInteger pubKeyX = ecPoint.getAffineX();
        int orderBitLength = getOrder().bitLength();
        int L = (orderBitLength / 2) + (orderBitLength % 2);
        
        BigInteger twoByL = BigInteger.ONE.shiftLeft(L);

        BigInteger RInverse = pubKeyX.mod(twoByL).add(twoByL);
        return RInverse;
    }

    private static BigInteger getOrder()
    {
        return EC_SPEC.getN();
    }

    private static int getCofactor()
    {
        return EC_SPEC.getH().intValue();
    }

}
