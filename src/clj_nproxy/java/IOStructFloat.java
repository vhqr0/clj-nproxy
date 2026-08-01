package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructFloat implements IIOStruct<Number> {
  private final ByteOrder order;

  public IOStructFloat(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    byte[] data = IIOStruct.readNBytes(is, 4);
    float dataFloat = ByteBuffer.wrap(data).order(order).getFloat(0);
    return Double.valueOf(dataFloat);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(4).order(order).putFloat(data.floatValue()).array();
    os.write(dataBytes);
  }
}
