package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface IIOStruct<T> {
  public T read(InputStream is) throws IOException;
  public void write(OutputStream os, T data) throws IOException;
}
