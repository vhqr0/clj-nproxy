package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructUint implements IIOStruct<Number> {
  private final IIOStruct<Number> intStruct;
  private final long mask;

  public IOStructUint(IIOStruct<Number> intStruct, long mask) {
    this.intStruct = intStruct;
    this.mask = mask;
  }

  @Override
  public Number read(InputStream is) throws IOException {
    return intStruct.read(is).longValue() & mask;
  }

  @Override
  public void write(OutputStream os, Number data) throws IOException {
    intStruct.write(os, data);
  }
}
