package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public final class IOStructInteger implements IIOStruct<Number> {
  private final ByteOrder order;

  public IOStructInteger(boolean isBigEndian) {
    order = isBigEndian ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    byte[] data = is.readNBytes(4);
    if (data.length != 4) throw new IOStructEOFException();
    int dataInt = ByteBuffer.wrap(data).order(order).getInt(0);
    return Long.valueOf(dataInt);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    byte[] dataBytes = ByteBuffer.allocate(4).order(order).putInt(data.intValue()).array();
    os.write(dataBytes);
  }
}
