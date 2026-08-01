package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructShort implements IIOStruct<Number> {
  private final ByteOrder order;

  public IOStructShort(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    byte[] data = IIOStruct.readNBytes(is, 2);
    short dataShort = ByteBuffer.wrap(data).order(order).getShort(0);
    return Long.valueOf(dataShort);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(2).order(order).putShort(data.shortValue()).array();
    os.write(dataBytes);
  }
}
