package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructByte implements IIOStruct<Long> {
  @Override
  public Long read(InputStream is) throws IOException {
    int n = is.read();
    if (n == -1) throw new IOStructEOFException();
    return Long.valueOf((byte) n);
  }

  @Override
  public void write(OutputStream os, Long data) throws IOException {
    os.write(data.byteValue());
  }
}
