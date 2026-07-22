package clj_nproxy.java;

import java.io.IOException;

public final class FnIOException extends IOException {
  public FnIOException(Throwable cause) {
    super(cause);
  }

  public static void throwIO(Throwable t) throws IOException {
    if (t instanceof IOException e) throw e;
    if (t instanceof RuntimeException e) throw e;
    if (t instanceof Error e) throw e;
    throw new FnIOException(t);
  }
}
