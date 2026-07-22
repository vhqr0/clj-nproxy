package clj_nproxy.java;

import clojure.lang.IFn;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public final class FilterCloseOutputStream extends FilterOutputStream {
  private final IFn closeFn;
  private boolean closed = false;

  public FilterCloseOutputStream(OutputStream out, IFn closeFn) {
    super(out);
    this.closeFn = closeFn;
  }

  @Override
  public void write(byte[] b) throws IOException {
    out.write(b);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    out.write(b, off, len);
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
