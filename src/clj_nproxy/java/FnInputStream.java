package clj_nproxy.java;

import clojure.lang.IFn;
import java.io.IOException;
import java.io.InputStream;

public final class FnInputStream extends InputStream {
  private static final byte[] EMPTY = new byte[0];

  private final IFn readFn;
  private final IFn closeFn;
  private byte[] buf = EMPTY;
  private int pos = 0;
  private boolean eof = false;
  private boolean closed = false;

  public FnInputStream(IFn readFn, IFn closeFn) {
    this.readFn = readFn;
    this.closeFn = closeFn;
  }

  private void tryClose() {
    try { close(); } catch (Throwable e) {}
  }

  private boolean ensure() throws IOException {
    if (pos < buf.length) return true;
    if (eof) return false;
    byte[] b;
    try {
      b = (byte[]) readFn.invoke();
    } catch (Throwable e) {
      tryClose();
      FnIOException.throwIO(e);
      return false;
    }
    if (b == null || b.length == 0) {
      eof = true;
      return false;
    }
    buf = b;
    pos = 0;
    return true;
  }

  @Override
  public int read() throws IOException {
    if (closed) throw new IOException("stream closed");
    if (!ensure()) return -1;
    return buf[pos++] & 0xff;
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    if (closed) throw new IOException("stream closed");
    if (len == 0) return 0;
    if (!ensure()) return -1;
    int n = Math.min(buf.length - pos, len);
    System.arraycopy(buf, pos, b, off, n);
    pos += n;
    return n;
  }

  @Override
  public int available() {
    return closed ? 0 : buf.length - pos;
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
