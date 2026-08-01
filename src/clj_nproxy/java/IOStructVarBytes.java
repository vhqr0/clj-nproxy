package clj_nproxy.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public final class IOStructVarBytes implements IIOStruct<byte[]> {
  private final IIOStruct<Number> lengthStruct;

  public IOStructVarBytes(IIOStruct<Number> lengthStruct) {
    this.lengthStruct = lengthStruct;
  }

  @Override
  public byte[] read(InputStream is) throws IOException {
    int length = Math.toIntExact(lengthStruct.read(is).longValue());
    return IIOStruct.readNBytes(is, length);
  }

  @Override
  public void write(OutputStream os, byte[] data) throws IOException {
    lengthStruct.write(os, Long.valueOf(data.length));
    os.write(data);
  }
}
