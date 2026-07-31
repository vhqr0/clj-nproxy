package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructNull implements IIOStruct<Object> {
  @Override
  public Object read(InputStream is) throws IOException {
    return null;
  }

  @Override
  public void write(OutputStream os, Object _data) throws IOException {}
}
