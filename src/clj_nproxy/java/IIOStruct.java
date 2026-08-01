package clj_nproxy.java;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public interface IIOStruct<T> {
  public T read(InputStream is) throws IOException;

  public void write(OutputStream os, T data) throws IOException;

  static byte[] readNBytes(InputStream is, int n) throws IOException {
    byte[] data = is.readNBytes(n);
    if (data.length != n) throw new IOStructEOFException();
    return data;
  }

  default T unpack(byte[] b) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(b);
    T data = read(bais);
    if (bais.available() > 0) throw new IOStructSurplusException();
    return data;
  }

  default byte[] pack(T data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    write(baos, data);
    return baos.toByteArray();
  }

  default List<T> unpackMany(byte[] b) throws IOException {
    ByteArrayInputStream bais = new ByteArrayInputStream(b);
    List<T> data = new ArrayList<>();
    while (bais.available() > 0) data.add(read(bais));
    return data;
  }

  default byte[] packMany(List<T> data) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    for (T subData : data) write(baos, subData);
    return baos.toByteArray();
  }
}
