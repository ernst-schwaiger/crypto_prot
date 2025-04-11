package net.its26;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;

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
}
