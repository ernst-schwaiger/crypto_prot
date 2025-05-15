package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

public class MQVTest 
{
    @Test void testSerializerDeserializer()
    {
        byte tmp[] = {(byte)0x23, (byte)0x45, (byte)0x67};
        MQV.Serializer ser = new MQV.Serializer();
        ser.ser1(0x89).ser4(0xabcdef01).serN(tmp);
        assertEquals(ser.serialized.length, 8);
        assertEquals(ser.serialized[0] & 0xff, 0x89);
        assertEquals(ser.serialized[1] & 0xff, 0xab);
        assertEquals(ser.serialized[2] & 0xff, 0xcd);
        assertEquals(ser.serialized[3] & 0xff, 0xef);
        assertEquals(ser.serialized[4] & 0xff, 0x01);
        assertEquals(ser.serialized[5] & 0xff, 0x23);
        assertEquals(ser.serialized[6] & 0xff, 0x45);
        assertEquals(ser.serialized[7] & 0xff, 0x67);

        MQV.Deserializer dser = new MQV.Deserializer(ser.serialized);
        assertEquals(dser.dser1(), (byte)0x89);
        assertEquals(dser.dser4(), 0xabcdef01);
        assertTrue(Arrays.equals(dser.dserN(tmp.length), tmp));
    }

    @Test void testSerDeSer()
    {
        try
        {
            Optional<KeyPair> optKeyPair = EC.generateKeyPair();
            assertTrue(optKeyPair.isPresent());
            ECPublicKey pubKey = (ECPublicKey)optKeyPair.get().getPublic();
            byte serialized[] = MQV.serializePubKey(pubKey.getW());
            ECPoint p = MQV.deserializePubKey(serialized);
            Optional<ECPublicKey> optDeserPubKey = EC.generatePublicKey(p, pubKey.getParams());

            assertTrue(optDeserPubKey.isPresent());
            assertTrue(optDeserPubKey.get().equals(pubKey));
        }
        catch(Exception e)
        {
            fail("MQV Key exchange failed");
        }
    }

    @Test void testSerializeToFromFile()
    {
        try (FileWriter writer = new FileWriter("ec_key_pair.pem"))
        {
            Optional<KeyPair> optKeyPair = EC.generateKeyPair();
            KeyPair keyPair = optKeyPair.get();
            writer.write("-----BEGIN PRIVATE KEY-----\n");
            writer.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
            writer.write("\n-----END PRIVATE KEY-----\n");

            writer.write("-----BEGIN PUBLIC KEY-----\n");
            writer.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            writer.write("\n-----END PUBLIC KEY-----\n");
        } 
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }

}
