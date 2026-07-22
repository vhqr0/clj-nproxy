package clj_nproxy.java;

import clojure.lang.IFn;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class FilterCloseInputStream extends FilterInputStream {
  private final IFn closeFn;
  private boolean closed = false;

  public FilterCloseInputStream(InputStream in, IFn closeFn) {
    super(in);
    this.closeFn = closeFn;
  }

  @Override
  public byte[] readAllBytes() throws IOException {
    return in.readAllBytes();
  }

  @Override
  public byte[] readNBytes(int len) throws IOException {
    return in.readNBytes(len);
  }

  @Override
  public int readNBytes(byte[] b, int off, int len) throws IOException {
    return in.readNBytes(b, off, len);
  }

  @Override
  public long transferTo(OutputStream out) throws IOException {
    return in.transferTo(out);
  }

  @Override
  public void close() throws IOException {
    if (closed) return;
    closed = true;
    if (closeFn != null) {
      try {
        closeFn.invoke();
      } catch (Throwable e) {
        FnIOException.throwIO(e);
      }
    }
  }
}
