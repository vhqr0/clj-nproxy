package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public record WSFrame(int op, boolean fin, byte[] mask, byte[] data) {
  public static final int OP_CONTINUATION = 0x0;
  public static final int OP_TEXT = 0x1;
  public static final int OP_BINARY = 0x2;
  public static final int OP_CLOSE = 0x8;
  public static final int OP_PING = 0x9;
  public static final int OP_PONG = 0xa;

  public static void maskInplace(byte[] data, byte[] mask) {
    for (int i = 0; i < data.length; i++)
      data[i] ^= mask[i & 3];
  }

  public static final class IOStruct implements IIOStruct<WSFrame> {
    public static final long DEFAULT_MAX_LENGTH = 64L * 1024 * 1024;

    private final long maxLength;

    public IOStruct() {
      this(DEFAULT_MAX_LENGTH);
    }

    public IOStruct(long maxLength) {
      this.maxLength = maxLength;
    }

    @Override
    public WSFrame read(InputStream is) throws IOException {
      int finOp = is.read();
      if (finOp == -1) throw new IOStructEOFException();
      boolean fin = (finOp & 0x80) != 0;
      int op = finOp & 0x7f;

      int maskLen = is.read();
      if (maskLen == -1) throw new IOStructEOFException();
      boolean masked = (maskLen & 0x80) != 0;
      long len = maskLen & 0x7f;
      if (len == 126) {
        byte[] b = IIOStruct.readNBytes(is, 2);
        len = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).getShort(0) & 0xffffL;
      } else if (len == 127) {
        byte[] b = IIOStruct.readNBytes(is, 8);
        len = ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).getLong(0);
      }
      if (len < 0 || len > maxLength) throw new IOStructDataException();

      byte[] mask = masked ? IIOStruct.readNBytes(is, 4) : null;
      byte[] data = IIOStruct.readNBytes(is, (int) len);
      if (masked) maskInplace(data, mask);
      return new WSFrame(op, fin, mask, data);
    }

    @Override
    public void write(OutputStream os, WSFrame frame) throws IOException {
      byte[] mask = frame.mask();
      byte[] data = frame.data();
      boolean masked = mask != null;
      int len = data.length;
      int maskBit = masked ? 0x80 : 0;

      os.write((frame.op() & 0x7f) | (frame.fin() ? 0x80 : 0));
      if (len >= 65536) {
        os.write(127 | maskBit);
        os.write(ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(len).array());
      } else if (len >= 126) {
        os.write(126 | maskBit);
        os.write(ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN).putShort((short) len).array());
      } else {
        os.write(len | maskBit);
      }
      if (masked) {
        os.write(mask);
        maskInplace(data, mask);
      }
      os.write(data);
    }
  }
}
