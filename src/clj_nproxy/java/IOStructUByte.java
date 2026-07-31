package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructUByte implements IIOStruct<Number> {
  @Override
  public Number read(InputStream is) throws IOException {
    int n = is.read();
    if (n == -1) throw new IOStructEOFException();
    return Long.valueOf(n);
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    os.write(data.byteValue());
  }
}
