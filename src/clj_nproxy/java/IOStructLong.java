package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructLong implements IIOStruct<Number> {
  private final ByteOrder order;

  public IOStructLong(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    byte[] data = IIOStruct.readNBytes(is, 8);
    long dataLong = ByteBuffer.wrap(data).order(order).getLong(0);
    return Long.valueOf(dataLong);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(8).order(order).putLong(data.longValue()).array();
    os.write(dataBytes);
  }
}
