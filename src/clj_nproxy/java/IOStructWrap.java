package clj_nproxy.java;

import clojure.lang.IFn;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructWrap implements IIOStruct<Object> {
  private final IIOStruct<Object> underStruct;
  private final IFn unpackFn;
  private final IFn packFn;

  public IOStructWrap(IIOStruct<Object> underStruct, IFn unpackFn, IFn packFn) {
    this.underStruct = underStruct;
    this.unpackFn = unpackFn;
    this.packFn = packFn;
  }

  @Override
  public Object read(InputStream is) throws IOException {
    Object underData = underStruct.read(is);
    try {
      return unpackFn.invoke(underData);
    } catch (Exception e) {
      throw new IOStructWrapException(e);
    }
  }

  @Override
  public void write(OutputStream os, Object data) throws IOException {
    Object underData = null;
    try {
      underData = packFn.invoke(data);
    } catch (Exception e) {
      throw new IOStructWrapException(e);
    }
    underStruct.write(os, underData);
  }
}
