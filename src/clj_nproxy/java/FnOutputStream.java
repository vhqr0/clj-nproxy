package clj_nproxy.java;

import clojure.lang.IFn;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

public final class FnOutputStream extends OutputStream {
  private final IFn writeFn;
  private final IFn closeFn;
  private boolean closed = false;

  public FnOutputStream(IFn writeFn, IFn closeFn) {
    this.writeFn = writeFn;
    this.closeFn = closeFn;
  }

  private void tryClose() {
    try { close(); } catch (Throwable e) {}
  }

  private void internalWrite(byte[] b) throws IOException {
    try {
      writeFn.invoke(b);
    } catch (Throwable e) {
      tryClose();
      FnIOException.throwIO(e);
    }
  }

  @Override
  public void write(int b) throws IOException {
    if (closed) throw new IOException("stream closed");
    internalWrite(new byte[] {(byte) b});
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    if (closed) throw new IOException("stream closed");
    if (len == 0) return;
    if (off == 0 && len == b.length)
      internalWrite(b);
    else
      internalWrite(Arrays.copyOfRange(b, off, off + len));
  }

  @Override
  public void write(byte[] b) throws IOException {
    if (closed) throw new IOException("stream closed");
    if (b.length == 0) return;
    internalWrite(b);
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
