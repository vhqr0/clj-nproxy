package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructFloat implements IIOStruct<Double> {
  private final ByteOrder order;

  public IOStructFloat(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Double read(InputStream is) throws IOException {
    byte[] data = is.readNBytes(4);
    if (data.length != 4) throw new IOStructEOFException();
    float dataFloat = ByteBuffer.wrap(data).order(order).getFloat(0);
    return Double.valueOf(dataFloat);
  }

  @Override
  public void write(OutputStream os, Double data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(4).order(order).putFloat(data.floatValue()).array();
    os.write(dataBytes);
  }
}
