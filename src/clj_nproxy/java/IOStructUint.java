package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructUint implements IIOStruct<Long> {
  private final IIOStruct<Long> intStruct;
  private final long mask;

  public IOStructUint(IIOStruct<Long> intStruct, long mask) {
    this.intStruct = intStruct;
    this.mask = mask;
  }

  @Override
  public Long read(InputStream is) throws IOException {
    return intStruct.read(is) & mask;
  }

  @Override
  public void write(OutputStream os, Long data) throws IOException {
    intStruct.write(os, data);
  }
}
