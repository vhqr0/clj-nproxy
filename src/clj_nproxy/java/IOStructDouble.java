package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructDouble implements IIOStruct<Number> {
  private final ByteOrder order;

  public IOStructDouble(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    byte[] data = is.readNBytes(8);
    if (data.length != 8) throw new IOStructEOFException();
    double dataDouble = ByteBuffer.wrap(data).order(order).getDouble(0);
    return Double.valueOf(dataDouble);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(8).order(order).putDouble(data.doubleValue()).array();
    os.write(dataBytes);
  }
}
