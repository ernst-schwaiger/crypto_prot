package net.its26;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;

public class MQV 
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
}
