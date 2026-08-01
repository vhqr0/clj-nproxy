package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructBytes implements IIOStruct<byte[]> {
  private final int length;

  public IOStructBytes(int length) {
    this.length = length;
  }

  @Override
  public byte[] read(InputStream is) throws IOException {
    return IIOStruct.readNBytes(is, length);
  }

  @Override
  public void write(OutputStream os, byte[] data) throws IOException {
    if (data.length != length) throw new IOStructDataException();
    os.write(data);
  }
}
